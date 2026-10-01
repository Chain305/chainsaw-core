package capability

// nuget_scanner.go detects capabilities in NuGet packages. A .nupkg ships
// compiled assemblies (lib/<tfm>/*.dll, runtimes/<rid>/lib/...), sometimes
// native libraries (runtimes/<rid>/native/), PowerShell install scripts
// (tools/*.ps1), MSBuild files that run in the consumer's build
// (build/*.targets) and C# sources copied into the consumer (content/,
// contentFiles/).
//
// Assemblies are read through their ECMA-335 metadata, not grepped. The
// #Strings heap holds a type's namespace and name as SEPARATE strings, so
// "System.Diagnostics" and "Process" both being present says only that the
// assembly mentions the type — Process.GetCurrentProcess().Id does that. The
// MemberRef table says which member is called: a MemberRef named "Start"
// whose parent TypeRef is System.Diagnostics.Process is a call to
// Process.Start, and nothing else is.
//
// Deliberately NOT dynamic eval, for the reasons given in maven_scanner.go:
// reflection (MethodInfo.Invoke, Activator), Reflection.Emit and
// Expression.Compile. Serializers, DI containers and ORMs use all three and
// they execute no code that was not compiled into the package. Dynamic eval
// is loading an assembly from a byte array, and the scripting / compiler
// APIs.

import (
	"encoding/binary"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

func init() {
	registerScanner(scanNuGet, "nuget")
}

// dotnetRule is one member of one type. members "*" matches any member;
// param0 constrains the first parameter ("string" or "byte[]").
type dotnetRule struct {
	cap     Capability
	ns, typ string
	members string // space-separated
	param0  string
}

var dotnetRules = []dotnetRule{
	{cap: CapShell, ns: "System.Diagnostics", typ: "Process", members: "Start"},
	{cap: CapShell, ns: "Microsoft.VisualBasic", typ: "Interaction", members: "Shell"},
	{cap: CapShell, ns: "System.Management.Automation", typ: "PowerShell", members: "Create"},
	{cap: CapShell, ns: "CliWrap", typ: "Cli", members: "Wrap"},

	{cap: CapNetwork, ns: "System.Net.Http", typ: "HttpClient", members: "Send SendAsync GetAsync PostAsync PutAsync PatchAsync DeleteAsync GetStringAsync GetByteArrayAsync GetStreamAsync"},
	{cap: CapNetwork, ns: "System.Net.Http", typ: "HttpMessageInvoker", members: "Send SendAsync"},
	{cap: CapNetwork, ns: "System.Net.Sockets", typ: "Socket", members: ".ctor Connect ConnectAsync Bind"},
	{cap: CapNetwork, ns: "System.Net.Sockets", typ: "TcpClient", members: ".ctor Connect ConnectAsync"},
	{cap: CapNetwork, ns: "System.Net.Sockets", typ: "TcpListener", members: ".ctor Start"},
	{cap: CapNetwork, ns: "System.Net.Sockets", typ: "UdpClient", members: ".ctor Connect Send SendAsync"},
	{cap: CapNetwork, ns: "System.Net", typ: "WebRequest", members: "Create CreateHttp"},
	{cap: CapNetwork, ns: "System.Net", typ: "HttpWebRequest", members: "GetResponse GetResponseAsync GetRequestStream"},
	{cap: CapNetwork, ns: "System.Net", typ: "WebClient", members: ".ctor"},
	{cap: CapNetwork, ns: "System.Net", typ: "HttpListener", members: "Start"},
	{cap: CapNetwork, ns: "System.Net", typ: "Dns", members: "GetHostEntry GetHostEntryAsync GetHostAddresses GetHostAddressesAsync"},
	{cap: CapNetwork, ns: "System.Net.WebSockets", typ: "ClientWebSocket", members: "ConnectAsync"},
	{cap: CapNetwork, ns: "System.Net.NetworkInformation", typ: "Ping", members: "Send SendPingAsync"},
	{cap: CapNetwork, ns: "System.Net.Mail", typ: "SmtpClient", members: "Send SendMailAsync"},

	{cap: CapEnvAccess, ns: "System", typ: "Environment", members: "GetEnvironmentVariable GetEnvironmentVariables ExpandEnvironmentVariables"},

	{cap: CapFilesystemRead, ns: "System.IO", typ: "File", members: "ReadAllText ReadAllTextAsync ReadAllBytes ReadAllBytesAsync ReadAllLines ReadAllLinesAsync ReadLines ReadLinesAsync OpenRead OpenText Open"},
	{cap: CapFilesystemRead, ns: "System.IO", typ: "Directory", members: "GetFiles EnumerateFiles GetDirectories EnumerateDirectories GetFileSystemEntries EnumerateFileSystemEntries"},
	{cap: CapFilesystemRead, ns: "System.IO", typ: "DirectoryInfo", members: "GetFiles EnumerateFiles GetDirectories EnumerateDirectories GetFileSystemInfos EnumerateFileSystemInfos"},
	{cap: CapFilesystemRead, ns: "System.IO", typ: "FileInfo", members: "OpenRead OpenText Open"},
	{cap: CapFilesystemRead, ns: "System.IO", typ: "FileStream", members: ".ctor", param0: "string"},
	{cap: CapFilesystemRead, ns: "System.IO", typ: "StreamReader", members: ".ctor", param0: "string"},

	{cap: CapFilesystemWrite, ns: "System.IO", typ: "File", members: "WriteAllText WriteAllTextAsync WriteAllBytes WriteAllBytesAsync WriteAllLines WriteAllLinesAsync AppendAllText AppendAllTextAsync AppendAllLines AppendAllLinesAsync AppendText Create CreateText Delete Move Copy Replace OpenWrite"},
	{cap: CapFilesystemWrite, ns: "System.IO", typ: "Directory", members: "CreateDirectory Delete Move"},
	{cap: CapFilesystemWrite, ns: "System.IO", typ: "DirectoryInfo", members: "Create CreateSubdirectory Delete MoveTo"},
	{cap: CapFilesystemWrite, ns: "System.IO", typ: "FileInfo", members: "Create CreateText AppendText OpenWrite Delete MoveTo CopyTo Replace"},
	{cap: CapFilesystemWrite, ns: "System.IO", typ: "StreamWriter", members: ".ctor", param0: "string"},

	{cap: CapNativeCode, ns: "System.Runtime.InteropServices", typ: "NativeLibrary", members: "Load TryLoad"},

	{cap: CapDynamicEval, ns: "System.Reflection", typ: "Assembly", members: "Load", param0: "byte[]"},
	{cap: CapDynamicEval, ns: "System", typ: "AppDomain", members: "Load", param0: "byte[]"},
	{cap: CapDynamicEval, ns: "System.Runtime.Loader", typ: "AssemblyLoadContext", members: "LoadFromStream"},
	{cap: CapDynamicEval, ns: "System.CodeDom.Compiler", typ: "CodeDomProvider", members: "CompileAssemblyFromSource"},
	{cap: CapDynamicEval, ns: "Microsoft.CodeAnalysis.CSharp.Scripting", typ: "CSharpScript", members: "EvaluateAsync RunAsync Create"},
	{cap: CapDynamicEval, ns: "Microsoft.CodeAnalysis", typ: "Compilation", members: "Emit"},
	{cap: CapDynamicEval, ns: "System.Management.Automation", typ: "ScriptBlock", members: "Create"},
}

// dotnetRuleIndex maps "ns.type::member" to rules; dotnetTypeIndex maps
// "ns.type" to the capabilities an assembly that DEFINES that type provides
// (the runtime packs and System.* packages implement these APIs themselves,
// so their calls are MethodDefs, not MemberRefs).
var dotnetRuleIndex, dotnetTypeIndex = func() (map[string][]dotnetRule, map[string][]Capability) {
	m, t := map[string][]dotnetRule{}, map[string][]Capability{}
	for _, r := range dotnetRules {
		key := r.ns + "." + r.typ
		for _, n := range strings.Fields(r.members) {
			m[key+"::"+n] = append(m[key+"::"+n], r)
		}
		t[key] = append(t[key], r.cap)
	}
	return m, t
}()

// Line rules for the text a nupkg ships.
var (
	psComments  = commentSyntax{line: []string{"#"}, blockOpen: "<#", blockClose: "#>"}
	xmlComments = commentSyntax{blockOpen: "<!--", blockClose: "-->"}

	// PowerShell is case-insensitive.
	nugetPS1Patterns = []linePattern{
		pat(CapShell, `(?i)\bStart-Process\b|\[(?:System\.)?Diagnostics\.Process\]::Start\b|\b(?:cmd|powershell|pwsh)(?:\.exe)?\s+[/-]`),
		pat(CapNetwork, `(?i)\bInvoke-WebRequest\b|\bInvoke-RestMethod\b|\b(?:iwr|irm)\b|Net\.WebClient\b|\bDownload(?:String|File|Data)\b|\bStart-BitsTransfer\b|Net\.Sockets\.TcpClient\b`),
		pat(CapEnvAccess, `(?i)\$env:|GetEnvironmentVariable`),
		pat(CapFilesystemWrite, `(?i)\b(?:Set-Content|Add-Content|Out-File|New-Item|Remove-Item|Copy-Item|Move-Item|Rename-Item)\b|\[(?:System\.)?IO\.File\]::(?:Write|Append|Delete|Move|Copy)`),
		pat(CapFilesystemRead, `(?i)\bGet-Content\b|\bGet-ChildItem\b|\[(?:System\.)?IO\.File\]::(?:Read|Open)`),
		pat(CapDynamicEval, `(?i)\bInvoke-Expression\b|\biex\b|\bAdd-Type\b|\[ScriptBlock\]::Create\b`),
	}

	nugetCSPatterns = []linePattern{
		pat(CapShell, `\bProcess\.Start\s*\(|\bnew\s+ProcessStartInfo\b`),
		pat(CapNetwork, `\bnew\s+(?:HttpClient|WebClient|TcpClient|UdpClient|TcpListener|ClientWebSocket)\s*\(|\bWebRequest\.Create(?:Http)?\s*\(`),
		pat(CapEnvAccess, `\bEnvironment\.(?:GetEnvironmentVariables?|ExpandEnvironmentVariables)\s*\(`),
		pat(CapFilesystemWrite, `\bFile\.(?:WriteAll\w*|AppendAll\w*|AppendText|Create\w*|Delete|Move|Copy|Replace|OpenWrite)\s*\(|\bDirectory\.(?:CreateDirectory|Delete|Move)\s*\(`),
		pat(CapFilesystemRead, `\bFile\.(?:ReadAll\w*|ReadLines\w*|OpenRead|OpenText|Open)\s*\(|\bDirectory\.(?:GetFiles|EnumerateFiles|GetDirectories|EnumerateDirectories|GetFileSystemEntries|EnumerateFileSystemEntries)\s*\(`),
		pat(CapNativeCode, `\[\s*(?:DllImport|LibraryImport)\s*\(|\bNativeLibrary\.(?:Load|TryLoad)\s*\(`),
		{
			cap: CapDynamicEval,
			re:  regexp.MustCompile(`\bAssembly\.Load\s*\(|\bLoadFromStream\s*\(|\bCSharpScript\.(?:EvaluateAsync|RunAsync|Create)\b|\bCompileAssemblyFromSource\s*\(`),
			// Assembly.Load("Name") loads an installed assembly by name.
			ignore: regexp.MustCompile(`\bAssembly\.Load\s*\(\s*@?"`),
		},
	}

	// MSBuild .targets/.props in build/ run inside every consumer's build.
	nugetMSBuildPatterns = []linePattern{
		pat(CapShell, `<Exec\b`),
		pat(CapNetwork, `<DownloadFile\b`),
	}
)

// scanNuGet walks an extracted .nupkg.
func scanNuGet(pkgDir string) (map[Capability][]Evidence, map[Capability]int, error) {
	if _, err := os.Stat(pkgDir); err != nil {
		return nil, nil, err
	}
	acc := newBinAcc()
	err := filepath.WalkDir(pkgDir, func(p string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return nil
		}
		if d.IsDir() {
			if p != pkgDir && commonSkipDirs[strings.ToLower(d.Name())] {
				return filepath.SkipDir
			}
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
		case ext == ".dll" || ext == ".exe" || ext == ".winmd":
			b, err := os.ReadFile(p)
			if err != nil {
				return nil
			}
			hits, err := assemblyHits(b)
			if errors.Is(err, errNotManaged) {
				// A PE with no CLI header is a native library.
				hits = map[Capability]string{CapNativeCode: "native (unmanaged) PE " + d.Name()}
			}
			acc.fileHits(rel, hits)
		case bundledNativeExts[ext] || (strings.Contains("/"+strings.ToLower(rel), "/native/") && ext != ".txt" && ext != ".md"):
			acc.fileHits(rel, map[Capability]string{CapNativeCode: "bundled native library " + d.Name()})
		}
		return nil
	})
	if err != nil {
		return nil, nil, err
	}
	for _, spec := range []sourceScanSpec{
		{exts: map[string]bool{".cs": true}, comments: cComments, patterns: nugetCSPatterns},
		{exts: map[string]bool{".ps1": true, ".psm1": true}, comments: psComments, patterns: nugetPS1Patterns},
		{exts: map[string]bool{".targets": true, ".props": true}, comments: xmlComments, patterns: nugetMSBuildPatterns},
	} {
		c, n, _ := scanSourceTree(pkgDir, spec)
		acc.merge(c, n)
	}
	// Blazor and static-web-asset packages ship JS.
	jsCaps, jsCounts, _ := scanNPMCounted(pkgDir)
	acc.merge(jsCaps, jsCounts)
	return acc.result()
}

var (
	errNotManaged = errors.New("capability: PE has no CLI metadata")
	errBadPE      = errors.New("capability: malformed PE/metadata")
)

// assemblyHits reads an assembly's metadata tables and returns one snippet
// per capability it references.
func assemblyHits(b []byte) (map[Capability]string, error) {
	md, err := readAssemblyMetadata(b)
	if err != nil {
		return nil, err
	}
	hits := map[Capability]string{}
	if md.pinvoke != "" {
		hits[CapNativeCode] = "P/Invoke (DllImport) " + md.pinvoke
	}
	for _, m := range md.memberRefs {
		for _, rule := range dotnetRuleIndex[m.typ+"::"+m.name] {
			if _, done := hits[rule.cap]; done {
				continue
			}
			if rule.param0 != "" && sigParam0(m.sig) != rule.param0 {
				continue
			}
			hits[rule.cap] = m.typ + "::" + m.name
		}
	}
	for _, t := range md.definedTypes {
		for _, c := range dotnetTypeIndex[t] {
			if _, done := hits[c]; !done {
				hits[c] = "defines " + t
			}
		}
	}
	return hits, nil
}

type dotnetMemberRef struct {
	typ, name string // typ is "Namespace.Type"
	sig       []byte
}

type assemblyMetadata struct {
	memberRefs   []dotnetMemberRef
	definedTypes []string // public TypeDefs, "Namespace.Type"
	pinvoke      string   // name of one P/Invoke method, "" if none
}

// Metadata table numbers (ECMA-335 II.22) up to MemberRef, plus the tables
// the coded indexes in them refer to.
const (
	tblModule, tblTypeRef, tblTypeDef, tblFieldPtr, tblField = 0x00, 0x01, 0x02, 0x03, 0x04
	tblMethodPtr, tblMethodDef, tblParamPtr, tblParam        = 0x05, 0x06, 0x07, 0x08
	tblInterfaceImpl, tblMemberRef                           = 0x09, 0x0A
	tblModuleRef, tblTypeSpec, tblAssemblyRef                = 0x1A, 0x1B, 0x23
)

// readAssemblyMetadata locates the CLI metadata in a PE image and decodes the
// TypeRef, TypeDef, MethodDef and MemberRef tables.
func readAssemblyMetadata(b []byte) (*assemblyMetadata, error) {
	le := binary.LittleEndian
	in := func(off, n int) bool { return off >= 0 && n >= 0 && off+n <= len(b) }
	if !in(0, 0x40) || b[0] != 'M' || b[1] != 'Z' {
		return nil, errBadPE
	}
	pe := int(le.Uint32(b[0x3C:]))
	if !in(pe, 24) || string(b[pe:pe+4]) != "PE\x00\x00" {
		return nil, errBadPE
	}
	nsec := int(le.Uint16(b[pe+6:]))
	optSize := int(le.Uint16(b[pe+20:]))
	opt := pe + 24
	if !in(opt, 2) {
		return nil, errBadPE
	}
	dirs := opt + 96 // PE32
	if le.Uint16(b[opt:]) == 0x20b {
		dirs = opt + 112 // PE32+
	}
	if !in(dirs+14*8, 8) || dirs+14*8+8 > opt+optSize {
		return nil, errNotManaged
	}
	cliRVA := int(le.Uint32(b[dirs+14*8:]))
	if cliRVA == 0 {
		return nil, errNotManaged
	}
	secs := opt + optSize
	rva := func(r int) int {
		for i := 0; i < nsec; i++ {
			s := secs + 40*i
			if !in(s, 40) {
				return -1
			}
			va, vs, raw, ptr := int(le.Uint32(b[s+12:])), int(le.Uint32(b[s+8:])), int(le.Uint32(b[s+16:])), int(le.Uint32(b[s+20:]))
			if r >= va && r < va+max(vs, raw) {
				return r - va + ptr
			}
		}
		return -1
	}
	cli := rva(cliRVA)
	if !in(cli, 16) {
		return nil, errBadPE
	}
	root := rva(int(le.Uint32(b[cli+8:])))
	if !in(root, 16) || le.Uint32(b[root:]) != 0x424A5342 { // "BSJB"
		return nil, errBadPE
	}
	vlen := int(le.Uint32(b[root+12:]))
	off := root + 16 + vlen
	if !in(off, 4) {
		return nil, errBadPE
	}
	nstreams := int(le.Uint16(b[off+2:]))
	off += 4
	var tables, strs, blobs []byte
	for i := 0; i < nstreams; i++ {
		if !in(off, 8) {
			return nil, errBadPE
		}
		so, sz := root+int(le.Uint32(b[off:])), int(le.Uint32(b[off+4:]))
		end := off + 8
		for end < len(b) && b[end] != 0 {
			end++
		}
		name := string(b[off+8 : min(end, len(b))])
		off = off + 8 + (end-(off+8)+4)&^3
		if !in(so, sz) {
			return nil, errBadPE
		}
		switch name {
		case "#~", "#-":
			tables = b[so : so+sz]
		case "#Strings":
			strs = b[so : so+sz]
		case "#Blob":
			blobs = b[so : so+sz]
		}
	}
	if len(tables) < 24 {
		return nil, errBadPE
	}
	return decodeTables(tables, strs, blobs)
}

func decodeTables(t, strs, blobs []byte) (*assemblyMetadata, error) {
	le := binary.LittleEndian
	heap := t[6]
	valid := le.Uint64(t[8:])
	var rows [64]int
	off := 24
	for i := 0; i < 64; i++ {
		if valid&(1<<i) == 0 {
			continue
		}
		if off+4 > len(t) {
			return nil, errBadPE
		}
		rows[i] = int(le.Uint32(t[off:]))
		off += 4
	}
	if heap&0x40 != 0 {
		off += 4
	}
	strSz, guidSz, blobSz := 2, 2, 2
	if heap&1 != 0 {
		strSz = 4
	}
	if heap&2 != 0 {
		guidSz = 4
	}
	if heap&4 != 0 {
		blobSz = 4
	}
	idx := func(tbl int) int {
		if rows[tbl] > 0xFFFF {
			return 4
		}
		return 2
	}
	coded := func(tagBits int, tbls ...int) int {
		for _, tb := range tbls {
			if rows[tb] >= 1<<(16-tagBits) {
				return 4
			}
		}
		return 2
	}
	resScope := coded(2, tblModule, tblModuleRef, tblAssemblyRef, tblTypeRef)
	typeDefOrRef := coded(2, tblTypeDef, tblTypeRef, tblTypeSpec)
	memberRefParent := coded(3, tblTypeDef, tblTypeRef, tblModuleRef, tblMethodDef, tblTypeSpec)
	rowSize := [tblMemberRef + 1]int{
		tblModule:        2 + strSz + 3*guidSz,
		tblTypeRef:       resScope + 2*strSz,
		tblTypeDef:       4 + 2*strSz + typeDefOrRef + idx(tblField) + idx(tblMethodDef),
		tblFieldPtr:      idx(tblField),
		tblField:         2 + strSz + blobSz,
		tblMethodPtr:     idx(tblMethodDef),
		tblMethodDef:     4 + 2 + 2 + strSz + blobSz + idx(tblParam),
		tblParamPtr:      idx(tblParam),
		tblParam:         2 + 2 + strSz,
		tblInterfaceImpl: idx(tblTypeDef) + typeDefOrRef,
		tblMemberRef:     memberRefParent + strSz + blobSz,
	}
	start := [tblMemberRef + 1]int{}
	for i := 0; i <= tblMemberRef; i++ {
		start[i] = off
		off += rows[i] * rowSize[i]
	}
	if off > len(t) {
		return nil, errBadPE
	}
	rd := func(o, n int) int {
		if n == 4 {
			return int(le.Uint32(t[o:]))
		}
		return int(le.Uint16(t[o:]))
	}
	str := func(i int) string {
		if i < 0 || i >= len(strs) {
			return ""
		}
		end := i
		for end < len(strs) && strs[end] != 0 {
			end++
		}
		return string(strs[i:end])
	}
	qual := func(ns, name string) string {
		if ns == "" {
			return name
		}
		return ns + "." + name
	}

	md := &assemblyMetadata{}
	typeRefs := make([]string, rows[tblTypeRef]+1)
	for i := 0; i < rows[tblTypeRef]; i++ {
		o := start[tblTypeRef] + i*rowSize[tblTypeRef] + resScope
		typeRefs[i+1] = qual(str(rd(o+strSz, strSz)), str(rd(o, strSz)))
	}
	for i := 0; i < rows[tblTypeDef]; i++ {
		o := start[tblTypeDef] + i*rowSize[tblTypeDef]
		if le.Uint32(t[o:])&0x7 == 1 { // tdPublic
			md.definedTypes = append(md.definedTypes, qual(str(rd(o+4+strSz, strSz)), str(rd(o+4, strSz))))
		}
	}
	for i := 0; i < rows[tblMethodDef]; i++ {
		o := start[tblMethodDef] + i*rowSize[tblMethodDef]
		if le.Uint16(t[o+6:])&0x2000 != 0 { // mdPinvokeImpl
			md.pinvoke = str(rd(o+8, strSz))
			break
		}
	}
	for i := 0; i < rows[tblMemberRef]; i++ {
		o := start[tblMemberRef] + i*rowSize[tblMemberRef]
		parent := rd(o, memberRefParent)
		if parent&7 != 1 { // only members of a TypeRef
			continue
		}
		tr := parent >> 3
		if tr <= 0 || tr >= len(typeRefs) {
			continue
		}
		md.memberRefs = append(md.memberRefs, dotnetMemberRef{
			typ:  typeRefs[tr],
			name: str(rd(o+memberRefParent, strSz)),
			sig:  mdBlob(blobs, rd(o+memberRefParent+strSz, blobSz)),
		})
	}
	return md, nil
}

// mdBlob returns the #Blob entry at i (ECMA-335 II.24.2.4 length prefix).
func mdBlob(h []byte, i int) []byte {
	v, n := mdCompressedUint(h, i)
	if n == 0 || i+n+v > len(h) {
		return nil
	}
	return h[i+n : i+n+v]
}

// mdCompressedUint decodes an ECMA-335 compressed unsigned integer at b[i],
// returning the value and its encoded length (0 if malformed).
func mdCompressedUint(b []byte, i int) (int, int) {
	if i < 0 || i >= len(b) {
		return 0, 0
	}
	switch c := b[i]; {
	case c&0x80 == 0:
		return int(c), 1
	case c&0xC0 == 0x80 && i+1 < len(b):
		return int(c&0x3F)<<8 | int(b[i+1]), 2
	case c&0xE0 == 0xC0 && i+3 < len(b):
		return int(c&0x1F)<<24 | int(b[i+1])<<16 | int(b[i+2])<<8 | int(b[i+3]), 4
	}
	return 0, 0
}

// sigParam0 names the first parameter of a method signature blob: "string",
// "byte[]", or "" for anything else (including a malformed blob, so a
// param0-constrained rule fails closed to "not matched").
func sigParam0(sig []byte) string {
	if len(sig) == 0 {
		return ""
	}
	p := 1
	if sig[0]&0x10 != 0 { // generic: skip generic parameter count
		_, n := mdCompressedUint(sig, p)
		p += n
	}
	count, n := mdCompressedUint(sig, p)
	if n == 0 || count == 0 {
		return ""
	}
	p = skipSigType(sig, p+n)                                          // return type
	for p >= 0 && p < len(sig) && (sig[p] == 0x1F || sig[p] == 0x20) { // custom modifiers
		_, n := mdCompressedUint(sig, p+1)
		p += 1 + n
	}
	if p < 0 || p >= len(sig) {
		return ""
	}
	switch {
	case sig[p] == 0x0E:
		return "string"
	case sig[p] == 0x1D && p+1 < len(sig) && sig[p+1] == 0x05:
		return "byte[]"
	}
	return ""
}

// skipSigType returns the offset just past the Type at sig[p], or -1.
func skipSigType(sig []byte, p int) int {
	if p < 0 || p >= len(sig) {
		return -1
	}
	c := sig[p]
	p++
	switch {
	case c >= 0x01 && c <= 0x0E, c == 0x16, c == 0x18, c == 0x19, c == 0x1C: // primitives, string, typedbyref, I, U, object
		return p
	case c == 0x0F, c == 0x10, c == 0x1D, c == 0x45: // ptr, byref, szarray, pinned
		return skipSigType(sig, p)
	case c == 0x11, c == 0x12, c == 0x13, c == 0x1E: // valuetype, class (token); var, mvar (number)
		_, n := mdCompressedUint(sig, p)
		if n == 0 {
			return -1
		}
		return p + n
	case c == 0x1F, c == 0x20: // cmod_reqd/opt token, then the type
		_, n := mdCompressedUint(sig, p)
		if n == 0 {
			return -1
		}
		return skipSigType(sig, p+n)
	case c == 0x15: // genericinst: class|valuetype, token, count, types
		if p >= len(sig) {
			return -1
		}
		_, n := mdCompressedUint(sig, p+1)
		if n == 0 {
			return -1
		}
		p += 1 + n
		cnt, n := mdCompressedUint(sig, p)
		if n == 0 {
			return -1
		}
		p += n
		for i := 0; i < cnt && p >= 0; i++ {
			p = skipSigType(sig, p)
		}
		return p
	}
	return -1 // arrays, function pointers: not needed by any rule
}
