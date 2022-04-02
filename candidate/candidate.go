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
These constants are subject to change once work begins on the minting algorithm
They are taken from the python distribution prototype
'H' is hash length
'M' is the length of a section of has digits
'N' is the number of m-digits matches to check
'K' is the number of iterations a candidate is
checked against the hash of any existing stash
concatenated with the candidate
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
// until the getPriK() "get private key" function works I'll use a dummy
// publickey address (I'll simply generate an rsa pair on the fly in InitCandidate())
// ..Encode fields random data & *rsa.PublicKey and hash with sha3
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
	// ShakeSum256 writes into hash
	sha3.ShakeSum256(hash, buf.Bytes())
	sha3.ShakeSum256(hash, buf.Bytes())
	candidate := string(hash[:])
	// TODO creating a byte buffer - skip last step and return bytes.
	// note, does not seem to be human readable characters
	// (i.e. nb:�9���y���u�j��U3�CD�Z���w2+-E����), will do research if this is ok
	return candidate[:hash_length], nil

}

// TODO: write functions and write a test function along with it.
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

// placeholder code. Once we have the Candidate struct in the boltdb
// we can create candidates from this db (we will have to have the user
// that is generating the candidates supply their PublicKey to locate
// and cache the Candidate struct in the db)
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

// TODO: implement haystack / UTXO db, likely: https://github.com/boltdb/bolt
