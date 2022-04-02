/*
TODO:
[x] getting undefined Candidate in Mint, need to fix this
[ ] build out mint function based on distribution.py algo
ISSUES:
[] An issue
*/
package mint

import (
	"fmt"

	"github.com/Eratosthenes/distribution/candidate"
)

// This file will check generate and check candidates against existing stashes
// in the bolt db, essentially implementing the mine() function in original_py_dist/distribution.py

// TODO work on this after testing is complete on generate.go/retrieve.go
func Mint(can *candidate.Candidate) {
	fmt.Println("starting mint....")
	candidate.GenerateHashCandidate(can)
}
