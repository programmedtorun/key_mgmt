// retrieve.go obtains the user's password, decrypts the private key and
// verifies that the user has the credentials to mint
package wallet

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"os"
	"path"

	"golang.org/x/crypto/pbkdf2"
)

const (
	INCORRECT_PASSWORD_EXIT = "\nYou have entered an incorrect password, and have no attempts remaining"
	PASSWORD_PROMPT         = "Please enter your password:\n> "
	CORRECT_PASSWORD        = "SUCCESS!! Correct password entered."
	PEM_ERROR               = "Failed to parse PEM block containing the key."
)

// GetPublicKey takes a wallet directory as an argument, prompts for
// the user to input their password, and returns the user's *rsa.PublicKey
func GetPublicKey(wallet_dir string, input_file *os.File) *rsa.PublicKey {
	if input_file == nil {
		input_file = os.Stdin
	}
	var err error
	var try_again bool = true
	var rsa_private_key *rsa.PrivateKey
	var attempts_left int = 3
	var generated_hashed_password []byte
	var retrieved_hashed_password = getHashedPassword(wallet_dir)
	for try_again {
		generated_hashed_password = obtainPassword(PASSWORD_PROMPT, wallet_dir, input_file)
		if string(generated_hashed_password) != string(retrieved_hashed_password) {
			attempts_left--
			if attempts_left == 0 {
				fmt.Println(INCORRECT_PASSWORD_EXIT)
				return nil
			}
			fmt.Printf("\nYou have entered an incorrect password, please try again. You have %v attempts left before the program terminates.\n", attempts_left)
			try_again = true
		} else {
			fmt.Println(CORRECT_PASSWORD)
			try_again = false
		}
	}
	rsa_private_key, err = getPrivateKey(generated_hashed_password, wallet_dir)
	if err != nil {
		fmt.Printf("Encountered an error getting private key, error: %v", err)
		return nil
	}
	return &rsa_private_key.PublicKey
}

// getPrivateKey takes the users pbkdf2 hashed password and the wallet directory name
// in which the *rsa.PrivateKey is encrypted and stored. Returns *rsa.PrivateKey
func getPrivateKey(hashed_password []byte, wallet_dir string) (*rsa.PrivateKey, error) {
	cipher_text_bytes := getCipher(wallet_dir)
	return decryptAES(hashed_password, cipher_text_bytes)
}

// obtainPassword prompts for password, opens the salt file and uses
// the contents - salt and user password to derive and return the pbkdf2 key
func obtainPassword(prompt, wallet_dir string, input_file *os.File) []byte {
	if input_file == nil {
		input_file = os.Stdin
	}
	var password string
	fmt.Print(prompt)
	fmt.Print("\033[8m")
	_, err := fmt.Fscanf(input_file, "%s", &password)
	fmt.Print("\033[28m")
	if err != nil {
		fmt.Printf("User input error: %v", err)
	}
	salt_bytes := getSalt(wallet_dir)
	hashed_password := pbkdf2.Key([]byte(password), salt_bytes, 4096, 32, sha1.New) //use sha256.New store
	return hashed_password
}

func getCipher(wallet_dir string) []byte {
	private_key_file_dir := os.Getenv("PRIVATE_KEY_FILE_DIR")
	f := path.Join(private_key_file_dir, wallet_dir, CIPHER_FILE)
	retrieved_cipher, err := os.ReadFile(f)
	if err != nil {
		log.Fatal(err)
	}
	return retrieved_cipher
}

// getHashedPassword returns the 32 length []byte key that was stored
func getHashedPassword(wallet_dir string) []byte {
	private_key_file_dir := os.Getenv("PRIVATE_KEY_FILE_DIR")
	f := path.Join(private_key_file_dir, wallet_dir, HASHED_PW_FILE)
	hashed_password, err := os.ReadFile(f)
	if err != nil {
		log.Fatal(err)
	}
	return hashed_password
}

// getSalt returns the []byte salt slice
func getSalt(wallet_dir string) []byte {
	private_key_file_dir := os.Getenv("PRIVATE_KEY_FILE_DIR")
	f := path.Join(private_key_file_dir, wallet_dir, SALT_FILE)
	salt, err := os.ReadFile(f)
	if err != nil {
		log.Fatal(err)
	}
	return salt
}

// decryptAES decrypts cipher text and returns *rsa.PrivateKey
func decryptAES(password []byte, cipher_text []byte) (*rsa.PrivateKey, error) {
	block, err := aes.NewCipher(password)
	if err != nil {
		fmt.Printf("Error occured in decrypting the cipher, aes.NewCipher() function error: %v", err)
		return nil, err
	}
	aes_GCM, err := cipher.NewGCM(block)
	if err != nil {
		fmt.Printf("Error occured in decrypting the cipher, cipher.NewGCM() function error: %v", err)
		return nil, err
	}
	nonce_size := aes_GCM.NonceSize()
	nonce, cip := cipher_text[:nonce_size], cipher_text[nonce_size:] // Extract the nonce from the encrypted data
	plain_text, err := aes_GCM.Open(nil, nonce, cip, nil)            // Decrypt
	if err != nil {
		fmt.Printf("Error occured in decrypting the cipher, aes_GCM.Open() function error: %v\n", err)
		return nil, err
	}
	return parseRsaPrivateKeyFromPemBytes(plain_text)
}

func parseRsaPrivateKeyFromPemBytes(private_PEM []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(private_PEM)
	if block == nil {
		return nil, errors.New(PEM_ERROR)
	}
	priv, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	return priv, nil
}
