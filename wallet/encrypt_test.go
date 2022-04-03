/*

 */
package wallet

import (
	"crypto/rand"
	"crypto/rsa"
	"log"
	"os"
	"testing"
	// "github.com/Eratosthenes/distribution/utils"
)

func TestInitCipherAndPassPhrase(t *testing.T) {
	fail = false
	input_file, err := writeToUserInputFile(TEST_PASS_PHRASE + ENTER)
	if err != nil {
		fail = true
		t.Errorf("Encountered a problem writing to user input file: %v", err)
	}
	defer input_file.Close()
	err = InitCipherAndPassPhrase(PK_TEST_FILE, input_file)
	if err != nil {
		fail = true
		t.Errorf("Encountered a problem in InitCipherAndPassPhrase error: %v, \nAuto pass phrase input was: %v", err, TEST_PASS_PHRASE)
	}
	printResult("TestInitCipherAndPassPhrase", fail)
}
func TestSetPassPhrase(t *testing.T) {
	fail = false
	input_file, err := writeToUserInputFile(TEST_PASS_PHRASE + ENTER)
	if err != nil {
		fail = true
		t.Errorf("Encountered a problem writing to user input file: %v", err)
	}
	defer input_file.Close()
	err = SetPassPhrase(PK_TEST_FILE, input_file)
	if err != nil {
		fail = true
		t.Errorf("Encountered a problem writing to user input file: %v", err)
	}
	printResult("TestSetPassPhrase", fail)
}

func TestCreatePassPhrase(t *testing.T) {
	fail = false
	input_file, err := writeToUserInputFile(TEST_PASS_PHRASE + ENTER)
	if err != nil {
		fail = true
		t.Errorf("Encountered a problem writing to user input file: %v", err)
	}
	defer input_file.Close()
	hashed_pass_phrase_and_salt := createPassPhrase("Enter pass phrase:", input_file)
	if len(hashed_pass_phrase_and_salt) < (32 + SALT_LENGTH) {
		fail = true
		t.Errorf("[]byte slice returned from createPassPhrase() is not long enough")
	}
	printResult("TestCreatePassPhrase", fail)
}

func TestWriteSaltCipherToFile(t *testing.T) {
	fail = false
	err := WriteSaltCipherToFile(PK_TEST_FILE, test_slice, os.Stdin)
	if err != nil {
		fail = true
		t.Errorf("Encountered an error writing to file: %v", err)
	}
	private_key_file_dir := os.Getenv("PRIVATE_KEY_FILE_DIR")
	file_string := private_key_file_dir + "/" + PK_TEST_FILE
	file_info, err := os.Lstat(file_string)
	if err != nil {
		fail = true
		log.Fatal(err)
	}
	mode := file_info.Mode()
	if mode != 0755 {
		fail = true
		t.Errorf("Got FileMode %v, but should be 0755", mode)
	}
	printResult("TestWriteSaltCipherToFile", fail)
}

// TestEncryptAES tests the encryption function - uses decryptAES to do so.
// Thus it's really a test for encryptAES() and decryptAES() functions
func TestEncryptAES(t *testing.T) {
	fail = false
	rsa_priv_key_initial, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		fail = true
		t.Errorf("Error generating rsa key: %v", err)
	}
	if err := rsa_priv_key_initial.Validate(); err != nil {
		fail = true
		t.Errorf("Error validating rsa key: %v", err)
	}
	private_key_pem_bytes := utils.ExportRsaPrivateKeyAsPemBytes(rsa_priv_key_initial)
	key, err := utils.GenerateRandomBytes(T_KEY_LENGTH)
	if err != nil {
		fail = true
		t.Errorf("Encountered an error in encryptAES() - GenerateRandomBytes(), error: %v, note: key length should be 32", err)
	}
	cipher, err := encryptAES(key, private_key_pem_bytes)
	if err != nil {
		fail = true
		t.Errorf("Encountered an error in encryptAES(), error: %v, note: key length is: %v, should be 32", err, len(key))
	}
	rsa_priv_key_final, err := decryptAES(key, cipher)
	if err != nil {
		fail = true
		t.Errorf("Encountered an error in decryptAES(), error: %v, note: key length is: %v, should be 32", err, len(key))
	}
	if string(utils.ExportRsaPrivateKeyAsPemBytes(rsa_priv_key_final)) != string(utils.ExportRsaPrivateKeyAsPemBytes(rsa_priv_key_initial)) {
		fail = true
		t.Errorf("Encountered an error *rsa.PrivateKey before and after encryption/decryption don't match. Note: key length is: %v, should be 32", len(key))
	}
	printResult("TestEncryptAES", fail)
}
