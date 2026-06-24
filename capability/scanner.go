package capability

// Analyze walks pkgDir and returns a capability Report for the given
// ecosystem. Today only ecosystem="npm" (and its aliases "yarn", "bun")
// returns a real report; all other ecosystems return an unsupported stub
// so callers can distinguish "clean scan" from "not yet implemented".
//
// pkgDir must be a directory containing the already-extracted package
// source. For npm packages this is the directory that contains package.json
// (the "package/" prefix inside the tarball is expected to have been
// stripped by the caller).
//
// A non-nil error is returned only for I/O failures on supported paths.
// Unsupported ecosystems always return (stub, nil).
func Analyze(pkgDir, ecosystem string) (*Report, error) {
	switch ecosystem {
	case "npm", "yarn", "bun":
		caps, err := ScanNPM(pkgDir)
		if err != nil {
			return nil, err
		}
		return &Report{
			Ecosystem:    ecosystem,
			Capabilities: caps,
		}, nil

	default:
		// TODO(capability/pip): add pip scanner for *.py files.
		// TODO(capability/rubygems): add rubygems scanner for *.rb files.
		// TODO(capability/cargo): add cargo scanner for *.rs files.
		return &Report{
			Ecosystem:   ecosystem,
			Unsupported: true,
		}, nil
	}
}
