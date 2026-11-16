package cli

// Shell-line tokenizer for `chainsaw guard agent-hook`.
//
// The shell guard sees argv: the shell has already split, unquoted and
// expanded it. The agent hook sees the raw command line an agent is about to
// hand to bash, so it has to do that splitting itself. This is NOT a shell
// parser. It does the least that keeps the two failure directions apart:
//
//   - A false DENY breaks an agent's ordinary work. So quoted text stays one
//     word (`git commit -m "npm install lodahs"` is a git command), heredoc
//     bodies and comments are skipped, and a redirection target is never an
//     argument (`npm i lodash > log.txt` installs lodash, not log.txt).
//   - A missed install is a miss, not a bypass of anything that existed: the
//     shell guard still runs when the agent's shell loads it, and the proxy
//     still sees every fetch. Constructs this cannot read statically
//     ($VAR, $(...), backticks) are MARKED on the word that holds them, so
//     the hook can ask instead of guessing.
//
// Commands inside $(...) and backticks are split out as commands of their own,
// so `echo $(npm i evil)` still surfaces `npm i evil`.

import "strings"

// shellWord is one word of a simple command after quote removal.
type shellWord struct {
	text string
	// dynamic: the word holds an unquoted or double-quoted $ or `, so its
	// value is only known when the shell runs it.
	dynamic bool
}

// shellCommands splits a command line into its simple commands, in order.
// Operators (&& || ; | & newline), subshell parens and command substitutions
// all end a command; empty commands are dropped.
func shellCommands(line string) [][]shellWord {
	var (
		cmds       [][]shellWord
		cur        []shellWord
		word       strings.Builder
		inWord     bool
		dyn        bool
		skipNext   bool // the next word is a redirection target
		inBacktick bool
		heredocs   []heredoc
	)
	endWord := func() {
		if inWord {
			if skipNext {
				skipNext = false
			} else {
				cur = append(cur, shellWord{text: word.String(), dynamic: dyn})
			}
		}
		word.Reset()
		inWord, dyn = false, false
	}
	endCmd := func() {
		endWord()
		if len(cur) > 0 {
			cmds = append(cmds, cur)
		}
		cur = nil
		skipNext = false
	}

	r := []rune(line)
	n := len(r)
	for i := 0; i < n; i++ {
		ch := r[i]
		switch {
		case ch == '\'':
			inWord = true
			for i++; i < n && r[i] != '\''; i++ {
				word.WriteRune(r[i])
			}
		case ch == '"':
			inWord = true
			for i++; i < n && r[i] != '"'; i++ {
				switch {
				case r[i] == '\\' && i+1 < n && strings.ContainsRune("$`\"\\\n", r[i+1]):
					i++
					if r[i] != '\n' {
						word.WriteRune(r[i])
					}
				case r[i] == '$' || r[i] == '`':
					dyn = true
					word.WriteRune(r[i])
				default:
					word.WriteRune(r[i])
				}
			}
		case ch == '\\':
			if i+1 < n {
				i++
				if r[i] != '\n' { // backslash-newline is a line continuation
					inWord = true
					word.WriteRune(r[i])
				}
			}
		case ch == '#' && !inWord:
			for i+1 < n && r[i+1] != '\n' {
				i++
			}
		case ch == '\n':
			endCmd()
			i = skipHeredocBodies(r, i+1, heredocs) - 1
			heredocs = nil
		case ch == ' ' || ch == '\t' || ch == '\r':
			endWord()
		case ch == ';' || ch == '&' || ch == '|' || ch == '(' || ch == ')':
			endCmd()
		case ch == '`':
			// Opening: leave a dynamic word in the command it interrupts (as
			// `$(` does via its `$`) and start the inner command. Closing: end
			// the inner command, and start the rest of the outer one with a
			// dynamic word, so that remainder is never read as a command.
			if !inBacktick {
				inWord, dyn = true, true
				word.WriteRune(ch)
				endCmd()
			} else {
				endCmd()
				inWord, dyn = true, true
				word.WriteRune(ch)
			}
			inBacktick = !inBacktick
		case ch == '$':
			inWord, dyn = true, true
			word.WriteRune(ch)
		case ch == '<' || ch == '>':
			// `2>` / `2>>`: the fd number is part of the operator, not a word.
			if inWord && !dyn && isDigits(word.String()) {
				word.Reset()
				inWord = false
			}
			endWord()
			if ch == '<' && i+2 < n && r[i+1] == '<' && r[i+2] != '<' {
				var d heredoc
				d, i = readHeredocDelim(r, i+2)
				if d.delim != "" {
					heredocs = append(heredocs, d)
				}
				continue
			}
			// Consume the rest of the operator: >> >| <> <<< >& <&.
			for i+1 < n && strings.ContainsRune("<>|", r[i+1]) {
				i++
			}
			if i+1 < n && r[i+1] == '&' {
				i++
				for i+1 < n && (isDigits(string(r[i+1])) || r[i+1] == '-') {
					i++
				}
				continue // `>&2`: duplicates a descriptor, no target word
			}
			skipNext = true
		default:
			inWord = true
			word.WriteRune(ch)
		}
	}
	endCmd()
	return cmds
}

type heredoc struct {
	delim     string
	stripTabs bool // <<- strips leading tabs from body lines and the delimiter
}

// readHeredocDelim reads the delimiter after `<<` (r[i] is the first rune
// after it). Quotes around the delimiter are removed. It returns the index of
// the delimiter's last rune.
func readHeredocDelim(r []rune, i int) (heredoc, int) {
	var d heredoc
	if i < len(r) && r[i] == '-' {
		d.stripTabs = true
		i++
	}
	for i < len(r) && (r[i] == ' ' || r[i] == '\t') {
		i++
	}
	var b strings.Builder
	for ; i < len(r); i++ {
		c := r[i]
		if c == ' ' || c == '\t' || c == '\n' || c == ';' || c == '&' || c == '|' || c == '<' || c == '>' || c == '(' || c == ')' {
			break
		}
		if c == '\'' || c == '"' || c == '\\' {
			continue
		}
		b.WriteRune(c)
	}
	d.delim = b.String()
	return d, i - 1
}

// skipHeredocBodies skips the bodies of pending heredocs, which start at r[i],
// and returns the index just past the last body's terminator line.
func skipHeredocBodies(r []rune, i int, docs []heredoc) int {
	for _, d := range docs {
		for i < len(r) {
			end := i
			for end < len(r) && r[end] != '\n' {
				end++
			}
			lineText := string(r[i:end])
			if d.stripTabs {
				lineText = strings.TrimLeft(lineText, "\t")
			}
			i = end + 1
			if lineText == d.delim {
				break
			}
		}
	}
	if i > len(r) {
		return len(r)
	}
	return i
}

func isDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}
