/*
TODO
[x] Write tests
*/
package wallet

import (
	"fmt"
	"testing"
)

func TestGetPublicKey(t *testing.T) {
	fail = false
	input_file, err := writeToUserInputFile(TEST_PASS_PHRASE + ENTER + TEST_PASS_PHRASE + ENTER)
	if err != nil {
		fail = true
		t.Fatal(err)
	}
	defer input_file.Close()
	err = SetPassPhrase(PK_TEST_FILE, input_file)
	if err != nil {
		fail = true
		t.Errorf("An error occured in SetPassPhrase")
	}
	rsa_public_key := GetPublicKey(PK_TEST_FILE, input_file)
	is_pub_key_type := fmt.Sprintf("%T", rsa_public_key)
	should_be_pub_key_type := "*rsa.PublicKey"
	if is_pub_key_type != should_be_pub_key_type {
		fail = true
		t.Errorf("Encountered a problem in GetPublicKey() should have successfully returned %v, but got %v", should_be_pub_key_type, is_pub_key_type)
	}
	printResult("TestGetPublicKey", fail)
}

func TestGetPrivateKey(t *testing.T) {
	fail = false
	input_file, err := writeToUserInputFile(TEST_PASS_PHRASE + ENTER + TEST_PASS_PHRASE + ENTER)
	if err != nil {
		fail = true
		t.Fatal(err)
	}
	defer input_file.Close()
	err = SetPassPhrase(PK_TEST_FILE, input_file)
	if err != nil {
		fail = true
		t.Errorf("An error occured in SetPassPhrase, error: %v", err)
	}
	hashed_pass_phrase := obtainPassPhrase("Enter pp", PK_TEST_FILE, input_file)
	rsa_private_key, err := getPrivateKey(hashed_pass_phrase, PK_TEST_FILE)
	if err != nil {
		t.Errorf("An error occured in getPrivateKey(), error: %v", err)
	}
	is_priv_key_type := fmt.Sprintf("%T", rsa_private_key)
	should_be_priv_key_type := "*rsa.PrivateKey"
	if is_priv_key_type != should_be_priv_key_type {
		fail = true
		t.Errorf("Encountered a problem in getPrivateKey() should have successfully returned %v, but got %v", should_be_priv_key_type, is_priv_key_type)
	}
	printResult("TestGetPrivateKey", fail)
}

func TestObtainPassPhrase(t *testing.T) {
	fail = false
	input_file, err := writeToUserInputFile(TEST_PASS_PHRASE + ENTER + TEST_PASS_PHRASE + ENTER)
	if err != nil {
		fail = true
		t.Fatal(err)
	}
	defer input_file.Close()
	err = SetPassPhrase(PK_TEST_FILE, input_file)
	if err != nil {
		fail = true
		t.Errorf("An error occured in SetPassPhrase, error: %v", err)
	}
	hashed_pass_phrase := obtainPassPhrase("Enter pp", PK_TEST_FILE, input_file)
	is_byte_slice_type := fmt.Sprintf("%T", hashed_pass_phrase)
	should_be_byte_slice_type := "[]uint8" // Hmm... this isn't []byte
	if is_byte_slice_type != should_be_byte_slice_type {
		fail = true
		t.Errorf("Encountered a problem in obtainPassPhrase() should have successfully returned %v, but got %v", should_be_byte_slice_type, is_byte_slice_type)
	}
	printResult("TestObtainPassPhrase", fail)
}

func TestGetSaltAndCipher(t *testing.T) {
	fail = false
	input_file, err := writeToUserInputFile(TEST_PASS_PHRASE + ENTER + TEST_PASS_PHRASE + ENTER)
	if err != nil {
		fail = true
		t.Fatal(err)
	}
	defer input_file.Close()
	err = SetPassPhrase(PK_TEST_FILE, input_file)
	if err != nil {
		fail = true
		t.Errorf("An error occured in SetPassPhrase, error: %v", err)
	}
	salt_and_cipher := getSaltAndCipher(PK_TEST_FILE)
	is_byte_slice_type := fmt.Sprintf("%T", salt_and_cipher)
	should_be_byte_slice_type := "[]uint8" // Hmm... this isn't []byte
	if is_byte_slice_type != should_be_byte_slice_type {
		fail = true
		t.Errorf("Encountered a problem in getSaltAndCipher() should have successfully returned %v, but got %v", should_be_byte_slice_type, is_byte_slice_type)
	}
	printResult("TestGetSaltAndCipher", fail)
}
