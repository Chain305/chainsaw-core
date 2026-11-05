package homebrew

// entryRootOwned: Homebrew does not run on Windows.
var entryRootOwned = func(string) bool { return false }
