package hook

import "fmt"

// writeWithBackup is the Wire-side boilerplate every manager shares:
// read the existing file (may be empty), backup if non-empty, then
// atomically write a sentinel-wrapped block. Factored out of the per-
// manager files so new managers don't copy 15 lines of identical logic.
func writeWithBackup(path, body string) error {
	data, err := readOrEmpty(path)
	if err != nil {
		return fmt.Errorf("read %s: %w", path, err)
	}
	if len(data) > 0 {
		if _, err := backup(path); err != nil {
			return fmt.Errorf("backup: %w", err)
		}
	}
	block := buildBlock(body)
	return writeAtomic(path, replaceOrAppend(data, block))
}

// unwireBlock is the Unwire-side boilerplate: read, require a sentinel
// block, backup, write without it. Returns ErrNotWired when the file
// doesn't contain a well-formed block.
func unwireBlock(path string) error {
	data, err := readOrEmpty(path)
	if err != nil {
		return fmt.Errorf("read %s: %w", path, err)
	}
	if len(data) == 0 || !hasSentinel(data) {
		return ErrNotWired
	}
	if _, err := backup(path); err != nil {
		return fmt.Errorf("backup: %w", err)
	}
	newData, removed := removeSentinel(data)
	if !removed {
		return ErrNotWired
	}
	return writeAtomic(path, newData)
}

// statusForConfig builds a Status by reading the user-scope config path
// once and reporting the installed-ness and wired-ness. configPathFn is
// the manager's ConfigPath() method; isInstalledFn is IsInstalled.
func statusForConfig(configPathFn func() (string, error), isInstalledFn func() bool) (Status, error) {
	path, err := configPathFn()
	if err != nil {
		return Status{}, err
	}
	data, err := readOrEmpty(path)
	if err != nil {
		return Status{ConfigPath: path, Installed: isInstalledFn()}, err
	}
	return Status{
		ConfigPath: path,
		Wired:      hasSentinel(data),
		Installed:  isInstalledFn(),
	}, nil
}
