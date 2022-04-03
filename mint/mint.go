/*
This file will generate HASH candidates via the Candidate struct derived from a Kaon
wallet's public key. After a candidate is generated the minting algorithm
will begin the proof-of-search process to find viable stashes for the wallet.
This is not yet implemented.
*/

package mint

import (
	"fmt"

	"github.com/programmedtorun/key_mgmt/candidate"
)

func Mint(can *candidate.Candidate) {
	fmt.Println("starting mint....")
	candidate.GenerateHashCandidate(can)
}
