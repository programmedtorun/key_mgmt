/*
Candidate is a structure derived from a public address that,
when given as input to the minting algorithm produces stashes
that are checked against existing stashes in the haystack,
if there are no collisions, the stash is created, added and
associated with the originator's address.
*/

package candidate

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/gob"
	"log"
	"time"

	"golang.org/x/crypto/sha3"
)

/*
Kaon minting algorithm variables are subject to change
once work begins on this algorithm. Variables are taken
from the python distribution prototype

'H' is hash length
'M' is the length of a section of has digits
'N' is the number of m-digits matches to check
'K' is the number of iterations a candidate is checked
against the hash of any existing stash concatenated with the candidate
*/

const (
	H int = 32
	M int = 3 // Might not be needed
	N int = 2
	K int = 10
)

// Will use this later to generate a candidate
type Candidate struct {
	PubAddress *rsa.PublicKey
	RandData   string
	Timestamp  time.Time
}

// New returns a new *Candidate.
func New(public_address *rsa.PublicKey, rand_data string) *Candidate {
	return &Candidate{public_address, rand_data, time.Now()}
}

// When run, this function assumes you have a valid wallet address
// via Candidate.PubAddress. For testing, an rsa pair can be generated
// on the fly in InitCandidate()
func GenerateHashCandidate(cf *Candidate) (string, error) {
	hash_length := H
	var buf bytes.Buffer
	enc := gob.NewEncoder(&buf)
	pubKeyBytes := x509.MarshalPKCS1PublicKey(cf.PubAddress)
	randBytes := []byte(cf.RandData)
	cBytes := append(pubKeyBytes, randBytes...)
	if err := enc.Encode(cBytes); err != nil {
		log.Fatal(err)
	}
	hash := make([]byte, hash_length)
	sha3.ShakeSum256(hash, buf.Bytes()) // writes into hash
	sha3.ShakeSum256(hash, buf.Bytes())
	candidate := string(hash[:])
	return candidate[:hash_length], nil

}

func GenRandBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	if err != nil {
		return nil, err
	}
	return b, nil
}

func GenRandStr(s int) (string, error) {
	b, err := GenRandBytes(s)
	return base64.URLEncoding.EncodeToString(b), err
}

// Placeholder/tester function. Users generating candidates will supply their PublicKey
func InitCandidate(hL int) (*Candidate, error) {
	rsaPriKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	if err := rsaPriKey.Validate(); err != nil {
		return nil, err
	}
	rsaPubKey := &rsaPriKey.PublicKey
	rData, err := GenRandStr(hL)
	if err != nil {
		return nil, err
	}
	cf := Candidate{PubAddress: rsaPubKey, RandData: rData}
	return &cf, nil
}

// TODO: implement haystack db, likely: https://github.com/boltdb/bolt
