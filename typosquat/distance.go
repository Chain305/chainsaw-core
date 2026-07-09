package typosquat

// DamerauLevenshtein computes the true Damerau-Levenshtein distance between
// two strings. Unlike the Optimal String Alignment variant, this satisfies
// the triangle inequality (required for BK-tree correctness).
//
// It counts insertions, deletions, substitutions, and transpositions of
// adjacent characters, and allows sequences of edits that OSA disallows.
func DamerauLevenshtein(a, b string) int {
	ra := []rune(a)
	rb := []rune(b)
	la := len(ra)
	lb := len(rb)

	if la == 0 {
		return lb
	}
	if lb == 0 {
		return la
	}

	// Build alphabet mapping: rune → last seen position in ra/rb.
	da := make(map[rune]int)

	// d is (la+2) × (lb+2), with d[0][*] and d[*][0] as sentinel rows/columns.
	maxDist := la + lb
	d := make([]int, (la+2)*(lb+2))
	w := lb + 2 // row width

	idx := func(i, j int) int { return i*w + j }

	d[idx(0, 0)] = maxDist
	for i := 0; i <= la; i++ {
		d[idx(i+1, 0)] = maxDist
		d[idx(i+1, 1)] = i
	}
	for j := 0; j <= lb; j++ {
		d[idx(0, j+1)] = maxDist
		d[idx(1, j+1)] = j
	}

	for i := 1; i <= la; i++ {
		db := 0 // last column in rb where rb[j-1] == ra[i-1]
		for j := 1; j <= lb; j++ {
			i1 := da[rb[j-1]] // last row in ra where ra[i1-1] == rb[j-1]
			j1 := db

			cost := 1
			if ra[i-1] == rb[j-1] {
				cost = 0
				db = j
			}

			sub := d[idx(i, j)] + cost // substitution
			ins := d[idx(i+1, j)] + 1  // insertion
			del := d[idx(i, j+1)] + 1  // deletion
			trans := d[idx(i1, j1)] +  // transposition
				(i - i1 - 1) + 1 + (j - j1 - 1)

			best := sub
			if ins < best {
				best = ins
			}
			if del < best {
				best = del
			}
			if trans < best {
				best = trans
			}
			d[idx(i+1, j+1)] = best
		}
		da[ra[i-1]] = i
	}

	return d[idx(la+1, lb+1)]
}
