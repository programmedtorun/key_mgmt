/*
TODO:
[ ] Ask Nate will the kaon stashes exist as keys and the values be found or not found booleans?
ISSUES:
[ ] An issue
*/
package boltdb

import (
	"fmt"
	"log"

	"github.com/boltdb/bolt"
)

// This file has Go driver functions for boltdb

var haystckValue string

// Writes key -> value pair to a bucket in boltdb/haystack.db
func UpdateHaystack(bucket, key, value string) error {
	db, err := bolt.Open("./boltdb/haystack.db", 0600, nil)
	if err != nil {
		log.Fatal(err)
		return err
	}
	if err := db.Update(func(tx *bolt.Tx) error {
		b, err := tx.CreateBucketIfNotExists([]byte(bucket))
		if err != nil {
			return err
		}
		if err := b.Put([]byte(key), []byte(value)); err != nil {
			return err
		}
		return nil
	}); err != nil {
		log.Fatal(err)
		return err
	}
	if err := db.Close(); err != nil {
		log.Fatal(err)
		return err
	}
	return nil
}

// Returns the value of a provided key in a provided bucket
func ViewValue(bucket string, key string) error {
	db, err := bolt.Open("./boltdb/haystack.db", 0600, nil)
	if err != nil {
		// log.Fatal(err)
		return err
	}
	db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("MyBucket"))
		v := b.Get([]byte("answer"))
		fmt.Printf("The answer is: %s\n", v)
		return nil
	})
	if err := db.View(func(tx *bolt.Tx) error {
		value := tx.Bucket([]byte(bucket)).Get([]byte(key))
		fmt.Printf("The value of %s is: %s\n", key, value)
		haystckValue = string(value)
		return nil
	}); err != nil {
		// log.Fatal(err)
		return err
	}
	if err := db.Close(); err != nil {
		// log.Fatal(err)
		return err
	}
	return nil
}
