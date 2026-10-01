package capability

// maven_scanner.go detects capabilities in compiled JVM artifacts (Maven
// Central and Gradle plugin jars, and Android .aar files).
//
// A jar holds .class files, not source. A class file's constant pool records
// every method it calls as a Methodref: an owner class, a method name and a
// descriptor, each a UTF-8 string. Resolving those references gives an exact
// "this class calls java/lang/Runtime.exec" — which a byte grep cannot: a
// class that merely holds the string literal "exec" and uses Runtime for
// availableProcessors() has both strings in its pool and calls neither.
//
// Deliberately NOT dynamic eval: reflection (Method.invoke, Class.forName)
// and invokedynamic/LambdaMetafactory. Every Java 8 lambda and most
// frameworks use them, they run no code that was not already compiled into
// the jar, and flagging them would make cap.dynamic_eval fire on nearly every
// jar. Dynamic eval here means code materialised at runtime from data:
// script engines, expression languages, runtime compilers and defineClass
// over a byte array.

import (
	"archive/zip"
	"encoding/binary"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

func init() {
	registerScanner(scanMaven, "maven", "gradle")
}

// jvmRule is one API a class may call. owner "" matches any owner (used for
// defineClass, which is usually invoked on the caller's own ClassLoader
// subclass). descPrefix/descHas constrain the method descriptor.
type jvmRule struct {
	cap        Capability
	owner      string
	names      string // space-separated method names
	descPrefix string
	descHas    string
}

var jvmRules = []jvmRule{
	{cap: CapShell, owner: "java/lang/Runtime", names: "exec"},
	{cap: CapShell, owner: "java/lang/ProcessBuilder", names: "start startPipeline"},

	{cap: CapNetwork, owner: "java/net/Socket", names: "<init> connect"},
	{cap: CapNetwork, owner: "java/net/ServerSocket", names: "<init> bind accept"},
	{cap: CapNetwork, owner: "java/net/DatagramSocket", names: "<init> connect send receive"},
	{cap: CapNetwork, owner: "java/net/MulticastSocket", names: "<init> joinGroup"},
	{cap: CapNetwork, owner: "java/net/URL", names: "openConnection openStream getContent"},
	{cap: CapNetwork, owner: "java/net/URLConnection", names: "connect getInputStream getOutputStream"},
	{cap: CapNetwork, owner: "java/net/HttpURLConnection", names: "connect getResponseCode getInputStream getOutputStream"},
	{cap: CapNetwork, owner: "javax/net/ssl/HttpsURLConnection", names: "connect getResponseCode getInputStream getOutputStream"},
	{cap: CapNetwork, owner: "java/net/http/HttpClient", names: "send sendAsync"},
	{cap: CapNetwork, owner: "java/nio/channels/SocketChannel", names: "open connect"},
	{cap: CapNetwork, owner: "java/nio/channels/ServerSocketChannel", names: "open"},
	{cap: CapNetwork, owner: "java/nio/channels/DatagramChannel", names: "open"},
	{cap: CapNetwork, owner: "java/nio/channels/AsynchronousSocketChannel", names: "open connect"},
	{cap: CapNetwork, owner: "javax/net/SocketFactory", names: "createSocket"},
	{cap: CapNetwork, owner: "javax/net/ssl/SSLSocketFactory", names: "createSocket"},
	// The dominant third-party clients: a library that makes its requests
	// through them never touches java/net itself.
	{cap: CapNetwork, owner: "okhttp3/OkHttpClient", names: "newCall newWebSocket"},
	{cap: CapNetwork, owner: "org/apache/http/client/HttpClient", names: "execute"},
	{cap: CapNetwork, owner: "org/apache/http/impl/client/CloseableHttpClient", names: "execute"},
	{cap: CapNetwork, owner: "org/apache/hc/client5/http/classic/HttpClient", names: "execute executeOpen"},
	{cap: CapNetwork, owner: "org/apache/hc/client5/http/impl/classic/CloseableHttpClient", names: "execute executeOpen"},
	{cap: CapNetwork, owner: "org/apache/hc/client5/http/impl/async/CloseableHttpAsyncClient", names: "execute"},
	{cap: CapNetwork, owner: "io/netty/bootstrap/Bootstrap", names: "connect"},
	{cap: CapNetwork, owner: "io/netty/bootstrap/AbstractBootstrap", names: "bind"},
	{cap: CapNetwork, owner: "io/netty/bootstrap/ServerBootstrap", names: "bind"},

	{cap: CapEnvAccess, owner: "java/lang/System", names: "getenv"},

	// The FileDescriptor constructors wrap an already-open descriptor
	// (log4j's ConsoleAppender wraps stdout), so only path/File ones count.
	{cap: CapFilesystemRead, owner: "java/io/FileInputStream", names: "<init>", descPrefix: "(Ljava/io/File;"},
	{cap: CapFilesystemRead, owner: "java/io/FileInputStream", names: "<init>", descPrefix: "(Ljava/lang/String;"},
	{cap: CapFilesystemRead, owner: "java/io/FileReader", names: "<init>", descPrefix: "(Ljava/io/File;"},
	{cap: CapFilesystemRead, owner: "java/io/FileReader", names: "<init>", descPrefix: "(Ljava/lang/String;"},
	{cap: CapFilesystemRead, owner: "java/io/RandomAccessFile", names: "<init>"},
	{cap: CapFilesystemRead, owner: "java/io/File", names: "list listFiles"},
	{cap: CapFilesystemRead, owner: "java/nio/channels/FileChannel", names: "open"},
	{cap: CapFilesystemRead, owner: "java/nio/file/Files", names: "readAllBytes readAllLines readString newInputStream newBufferedReader lines list walk find newDirectoryStream newByteChannel"},

	{cap: CapFilesystemWrite, owner: "java/io/FileOutputStream", names: "<init>", descPrefix: "(Ljava/io/File;"},
	{cap: CapFilesystemWrite, owner: "java/io/FileOutputStream", names: "<init>", descPrefix: "(Ljava/lang/String;"},
	{cap: CapFilesystemWrite, owner: "java/io/FileWriter", names: "<init>", descPrefix: "(Ljava/io/File;"},
	{cap: CapFilesystemWrite, owner: "java/io/FileWriter", names: "<init>", descPrefix: "(Ljava/lang/String;"},
	{cap: CapFilesystemWrite, owner: "java/io/PrintWriter", names: "<init>", descPrefix: "(Ljava/lang/String;"},
	{cap: CapFilesystemWrite, owner: "java/io/PrintWriter", names: "<init>", descPrefix: "(Ljava/io/File;"},
	{cap: CapFilesystemWrite, owner: "java/io/PrintStream", names: "<init>", descPrefix: "(Ljava/lang/String;"},
	{cap: CapFilesystemWrite, owner: "java/io/PrintStream", names: "<init>", descPrefix: "(Ljava/io/File;"},
	{cap: CapFilesystemWrite, owner: "java/io/File", names: "delete renameTo mkdir mkdirs createNewFile createTempFile deleteOnExit setWritable setExecutable"},
	{cap: CapFilesystemWrite, owner: "java/nio/file/Files", names: "write writeString newOutputStream newBufferedWriter delete deleteIfExists move copy createFile createDirectory createDirectories createTempFile createTempDirectory createSymbolicLink createLink"},

	{cap: CapNativeCode, owner: "java/lang/System", names: "loadLibrary load"},
	{cap: CapNativeCode, owner: "java/lang/Runtime", names: "loadLibrary load"},
	{cap: CapNativeCode, owner: "com/sun/jna/Native", names: "load loadLibrary register"},
	{cap: CapNativeCode, owner: "jnr/ffi/LibraryLoader", names: "create"},
	{cap: CapNativeCode, owner: "java/lang/foreign/Linker", names: "nativeLinker"},
	{cap: CapNativeCode, owner: "java/lang/foreign/SymbolLookup", names: "libraryLookup"},

	{cap: CapDynamicEval, owner: "javax/script/ScriptEngine", names: "eval"},
	{cap: CapDynamicEval, owner: "javax/script/Compilable", names: "compile"},
	{cap: CapDynamicEval, owner: "", names: "defineClass", descHas: "[B"},
	{cap: CapDynamicEval, owner: "", names: "defineClass", descHas: "Ljava/nio/ByteBuffer;"},
	{cap: CapDynamicEval, owner: "", names: "defineHiddenClass defineAnonymousClass"},
	{cap: CapDynamicEval, owner: "javax/tools/JavaCompiler", names: "getTask run"},
	{cap: CapDynamicEval, owner: "groovy/lang/GroovyShell", names: "evaluate parse run"},
	{cap: CapDynamicEval, owner: "groovy/lang/GroovyClassLoader", names: "parseClass"},
	{cap: CapDynamicEval, owner: "groovy/util/Eval", names: "me x xy xyz"},
	{cap: CapDynamicEval, owner: "org/mozilla/javascript/Context", names: "evaluateString evaluateReader compileString compileReader"},
	{cap: CapDynamicEval, owner: "org/graalvm/polyglot/Context", names: "eval"},
	{cap: CapDynamicEval, owner: "bsh/Interpreter", names: "eval source"},
	{cap: CapDynamicEval, owner: "jdk/jshell/JShell", names: "eval"},
	{cap: CapDynamicEval, owner: "org/codehaus/janino/SimpleCompiler", names: "cook"},
	{cap: CapDynamicEval, owner: "org/codehaus/janino/ScriptEvaluator", names: "cook"},
	{cap: CapDynamicEval, owner: "org/mvel2/MVEL", names: "eval compileExpression executeExpression"},
	{cap: CapDynamicEval, owner: "ognl/Ognl", names: "parseExpression getValue"},
	{cap: CapDynamicEval, owner: "org/springframework/expression/ExpressionParser", names: "parseExpression"},
	{cap: CapDynamicEval, owner: "org/apache/commons/jexl3/JexlEngine", names: "createExpression createScript"},
}

// jvmRuleIndex maps "owner.name" (owner "" for any-owner rules) to rules.
var jvmRuleIndex = func() map[string][]jvmRule {
	m := map[string][]jvmRule{}
	for _, r := range jvmRules {
		for _, n := range strings.Fields(r.names) {
			m[r.owner+"."+n] = append(m[r.owner+"."+n], r)
		}
	}
	return m
}()

// bundledNativeExts are shared libraries a jar or nupkg may carry.
var bundledNativeExts = map[string]bool{".so": true, ".dylib": true, ".jnilib": true, ".a": true}

// binAcc accumulates evidence and per-file counts for the binary scanners.
type binAcc struct {
	caps   map[Capability][]Evidence
	counts map[Capability]int
}

func newBinAcc() *binAcc {
	return &binAcc{caps: map[Capability][]Evidence{}, counts: map[Capability]int{}}
}

// fileHits records at most one count per capability for one file.
func (a *binAcc) fileHits(file string, hits map[Capability]string) {
	for c, snip := range hits {
		a.counts[c]++
		addNPMEvidence(a.caps, c, Evidence{File: file, Snippet: truncateBytes([]byte(snip), MaxSnippetLen)})
	}
}

// merge folds another scanner's output in (the npm scan of bundled JS, the
// line scanners for .cs/.ps1).
func (a *binAcc) merge(caps map[Capability][]Evidence, counts map[Capability]int) {
	for c, evs := range caps {
		if _, ok := a.caps[c]; !ok {
			a.caps[c] = nil
		}
		for _, ev := range evs {
			addNPMEvidence(a.caps, c, ev)
		}
	}
	for c, n := range counts {
		a.counts[c] += n
	}
}

func (a *binAcc) result() (map[Capability][]Evidence, map[Capability]int, error) {
	if len(a.caps) == 0 {
		return nil, nil, nil
	}
	return a.caps, a.counts, nil
}

// scanMaven walks an extracted jar. Nothing is skipped by directory name: a
// jar has no test tree (Maven leaves src/test out of it), so a class under a
// package called "test" is shipped, loadable code — skipping it would be an
// evasion path. Nested jars and aars (Android's classes.jar, fat jars) are
// read one level deep.
func scanMaven(pkgDir string) (map[Capability][]Evidence, map[Capability]int, error) {
	if _, err := os.Stat(pkgDir); err != nil {
		return nil, nil, err
	}
	acc := newBinAcc()
	err := filepath.WalkDir(pkgDir, func(p string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil || d.IsDir() {
			return nil
		}
		rel, _ := filepath.Rel(pkgDir, p)
		rel = filepath.ToSlash(rel)
		ext := strings.ToLower(filepath.Ext(d.Name()))
		info, err := d.Info()
		if err != nil || info.Size() > MaxFileScanBytes*4 {
			return nil
		}
		switch {
		case ext == ".class":
			if b, err := os.ReadFile(p); err == nil {
				acc.fileHits(rel, classHits(b))
			}
		case ext == ".jar" || ext == ".aar" || ext == ".war":
			scanNestedJar(p, rel, acc)
		case bundledNativeExts[ext] || ext == ".dll":
			acc.fileHits(rel, map[Capability]string{CapNativeCode: "bundled native library " + d.Name()})
		}
		return nil
	})
	if err != nil {
		return nil, nil, err
	}
	// WebJars and mvnpm repackage npm packages as jars; their code is JS.
	jsCaps, jsCounts, _ := scanNPMCounted(pkgDir)
	acc.merge(jsCaps, jsCounts)
	return acc.result()
}

// scanNestedJar scans the .class and native-library entries of an archive
// found inside the artifact. It does not recurse further.
func scanNestedJar(path, rel string, acc *binAcc) {
	zr, err := zip.OpenReader(path)
	if err != nil {
		return
	}
	defer zr.Close()
	for _, zf := range zr.File {
		if zf.FileInfo().IsDir() || zf.UncompressedSize64 > MaxFileScanBytes*4 {
			continue
		}
		ext := strings.ToLower(filepath.Ext(zf.Name))
		name := rel + "!/" + zf.Name
		switch {
		case ext == ".class":
			rc, err := zf.Open()
			if err != nil {
				continue
			}
			b, err := io.ReadAll(io.LimitReader(rc, MaxFileScanBytes*4))
			_ = rc.Close()
			if err == nil {
				acc.fileHits(name, classHits(b))
			}
		case bundledNativeExts[ext] || ext == ".dll":
			acc.fileHits(name, map[Capability]string{CapNativeCode: "bundled native library " + filepath.Base(zf.Name)})
		}
	}
}

// classHits resolves a class file's method references against jvmRules and
// returns one snippet per capability. An unparseable file yields nothing.
func classHits(b []byte) map[Capability]string {
	refs, hasNative, err := parseClassRefs(b)
	if err != nil {
		return nil
	}
	hits := map[Capability]string{}
	if hasNative {
		hits[CapNativeCode] = "declares a native (JNI) method"
	}
	for _, r := range refs {
		for _, key := range [2]string{r.owner + "." + r.name, "." + r.name} {
			for _, rule := range jvmRuleIndex[key] {
				if _, done := hits[rule.cap]; done {
					continue
				}
				if !strings.HasPrefix(r.desc, rule.descPrefix) || !strings.Contains(r.desc, rule.descHas) {
					continue
				}
				hits[rule.cap] = r.owner + "." + r.name + r.desc
			}
		}
	}
	return hits
}

type jvmRef struct{ owner, name, desc string }

var errBadClass = errors.New("capability: malformed class file")

// parseClassRefs returns every Methodref/InterfaceMethodref in a class file's
// constant pool, and whether the class declares a native method.
func parseClassRefs(b []byte) (refs []jvmRef, hasNative bool, err error) {
	if len(b) < 10 || binary.BigEndian.Uint32(b) != 0xCAFEBABE {
		return nil, false, errBadClass
	}
	n := int(binary.BigEndian.Uint16(b[8:]))
	utf8 := make([]string, n)
	class := make([]int, n)  // Class -> Utf8 index
	nat := make([][2]int, n) // NameAndType -> name, descriptor Utf8 indexes
	var methodrefs [][2]int  // class index, NameAndType index
	off := 10
	u2 := func(o int) int { return int(binary.BigEndian.Uint16(b[o:])) }
	for i := 1; i < n; i++ {
		if off >= len(b) {
			return nil, false, errBadClass
		}
		tag := b[off]
		var size int
		switch tag {
		case 1: // Utf8
			if off+3 > len(b) {
				return nil, false, errBadClass
			}
			l := u2(off + 1)
			if off+3+l > len(b) {
				return nil, false, errBadClass
			}
			utf8[i] = string(b[off+3 : off+3+l])
			size = 3 + l
		case 3, 4, 9, 17, 18: // Integer, Float, Fieldref, Dynamic, InvokeDynamic
			size = 5
		case 5, 6: // Long, Double take two slots
			size = 9
			i++
		case 7, 8, 16, 19, 20: // Class, String, MethodType, Module, Package
			size = 3
		case 10, 11, 12: // Methodref, InterfaceMethodref, NameAndType
			size = 5
		case 15: // MethodHandle
			size = 4
		default:
			return nil, false, errBadClass
		}
		if off+size > len(b) {
			return nil, false, errBadClass
		}
		switch tag {
		case 7:
			class[i] = u2(off + 1)
		case 10, 11:
			methodrefs = append(methodrefs, [2]int{u2(off + 1), u2(off + 3)})
		case 12:
			nat[i] = [2]int{u2(off + 1), u2(off + 3)}
		}
		off += size
	}
	at := func(i int) int {
		if i <= 0 || i >= n {
			return 0
		}
		return i
	}
	for _, mr := range methodrefs {
		c, t := at(mr[0]), at(mr[1])
		refs = append(refs, jvmRef{owner: utf8[at(class[c])], name: utf8[at(nat[t][0])], desc: utf8[at(nat[t][1])]})
	}
	return refs, classHasNativeMethod(b, off), nil
}

// classHasNativeMethod walks the fields and methods that follow the constant
// pool and reports whether any method carries ACC_NATIVE.
func classHasNativeMethod(b []byte, off int) bool {
	u2 := func() (int, bool) {
		if off+2 > len(b) {
			return 0, false
		}
		v := int(binary.BigEndian.Uint16(b[off:]))
		off += 2
		return v, true
	}
	off += 6 // access_flags, this_class, super_class
	ifaces, ok := u2()
	if !ok {
		return false
	}
	off += 2 * ifaces
	// members skips fields (native=false) or scans methods (native=true).
	members := func(methods bool) bool {
		count, ok := u2()
		if !ok {
			return false
		}
		for i := 0; i < count; i++ {
			flags, ok := u2()
			if !ok {
				return false
			}
			if methods && flags&0x0100 != 0 {
				return true
			}
			off += 4 // name, descriptor
			attrs, ok := u2()
			if !ok {
				return false
			}
			for j := 0; j < attrs; j++ {
				if off+6 > len(b) {
					return false
				}
				off += 6 + int(binary.BigEndian.Uint32(b[off+2:]))
			}
		}
		return false
	}
	members(false)
	return members(true)
}
