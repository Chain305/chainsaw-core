package typosquat

import "sync"

// BKTree is a Burkhard-Keller tree for fast approximate string matching
// using edit distance. It prunes the search space via the triangle inequality,
// typically examining <5% of entries for threshold ≤ 2.
type BKTree struct {
	mu   sync.RWMutex
	root *bkNode
	size int
}

type bkNode struct {
	word     string
	children map[int]*bkNode
}

// NewBKTree creates an empty BK-tree.
func NewBKTree() *BKTree {
	return &BKTree{}
}

// Insert adds a word to the tree. Not safe for concurrent use with queries;
// build the tree first, then query. For rebuilds, create a new tree.
func (t *BKTree) Insert(word string) {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.root == nil {
		t.root = &bkNode{word: word, children: make(map[int]*bkNode)}
		t.size++
		return
	}

	node := t.root
	for {
		d := DamerauLevenshtein(word, node.word)
		if d == 0 {
			return // duplicate
		}
		child, ok := node.children[d]
		if !ok {
			node.children[d] = &bkNode{word: word, children: make(map[int]*bkNode)}
			t.size++
			return
		}
		node = child
	}
}

// Search returns all words within the given edit distance threshold.
func (t *BKTree) Search(query string, threshold int) []SearchResult {
	t.mu.RLock()
	defer t.mu.RUnlock()

	if t.root == nil {
		return nil
	}

	var results []SearchResult
	var stack []*bkNode
	stack = append(stack, t.root)

	for len(stack) > 0 {
		node := stack[len(stack)-1]
		stack = stack[:len(stack)-1]

		d := DamerauLevenshtein(query, node.word)
		if d <= threshold {
			results = append(results, SearchResult{
				Word:     node.word,
				Distance: d,
			})
		}

		// Triangle inequality pruning: only visit children with
		// distances in [d-threshold, d+threshold].
		low := d - threshold
		high := d + threshold
		for childDist, child := range node.children {
			if childDist >= low && childDist <= high {
				stack = append(stack, child)
			}
		}
	}

	return results
}

// SearchResult holds a match from BKTree.Search.
type SearchResult struct {
	Word     string
	Distance int
}

// Size returns the number of words in the tree.
func (t *BKTree) Size() int {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.size
}
