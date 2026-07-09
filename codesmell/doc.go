// Package codesmell holds the per-language static pattern scanners used by
// Wave 3 of the Socket-gap implementation plan (SOCKET_GAP_IMPLEMENTATION_PLAN.md §10).
//
// Every scanner here is a pure function over a file map (path → bytes). The
// intelligence providers in internal/intelligence/provider_codesmell_*.go
// feed them the shared ArtifactFileMap produced by the Wave-0 consolidator
// (internal/intelligence/artifactmap) so decompression happens once per Scan.
//
// Nine ConditionTypes are implemented in this package:
//
//   - UsesEval            — eval() / Function() / exec() dynamic code eval.
//   - NetworkAccess       — http / fetch / raw sockets.
//   - ShellAccess         — child_process / subprocess / os.system / Runtime.exec.
//   - FilesystemAccess    — fs.* / open() / std::fs.
//   - EnvVarAccess        — process.env / os.environ / std::env::var.
//   - NativeBinaryPresent — shipped .node/.so/.dll/.dylib or binding.gyp.
//   - HighEntropyStrings  — candidate leaked secrets (entropy + curated patterns).
//   - URLStrings          — http(s) URLs in source files (via mvdan.cc/xurls/v2).
//   - MinifiedCode        — heuristic line-length + identifier-shortness bundle.
//
// All scanners are bounded so a pathological archive cannot DoS the proxy:
//
//   - MaxFilesPerScan caps how many files from the map each scanner visits.
//   - MaxBytesPerFile caps the per-file byte window each scanner inspects.
//
// Hard perf budget (per scanner) is 500 ms on a representative 10 MB /
// 200-file artifact; see the _bench.go files for the in-tree microbenches.
package codesmell
