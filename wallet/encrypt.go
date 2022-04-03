/*
  encrypt.go sets the user's password by calling InitCipherAndPassword(), the user's password
  is salted and is hashed, the key is then used to encrypt a wallet file's private key
*/

package wallet

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"regexp"
	"strings"

	"golang.org/x/crypto/pbkdf2"
)

const (
	PASS_PHRASE_HASH_SUCCESS = "\nSUCCESS!! Your pass phrase has been hashed."
	PASS_PHRASE_MATCH_ERROR  = "\nPass phrases do not match please try again. Enter a pass phrase.\n> "
	PASS_PHRASE_SPACE_ERROR  = "\nYou entered a space in you pass phrase. Please enter a new pass phrase.\n> "
	RSA_ENCRYPTED_SUCCESS    = "\nSUCCESS!! Your RSA Private Key has been encrypted."
	CONFIRM_PASS_PHRASE      = "\nType your pass phrase again, to confirm selection.\n> "
	STORED_SUCCESS           = "\nSUCCESS!! Your %s has been stored in the file: %s"
	PASS_PHRASE_RULES        = "Your pass phrase must be:\n-> Alphanumeric, uppercase letters OK\n-> Free of spaces\n-> Between 8 - 32 characters\n-> Special characters OK\n-> Type 'e' and hit return to exit this process\n\nEnter your new pass phrase.\n> "
	HASHED_PW_FILE           = "hashed_pw.dat"
	CIPHER_FILE              = "cipher.dat"
	SALT_FILE                = "salt.dat"
)

// InitCipherAndPassword initiates the password process
func InitCipherAndPassword(wallet_dir string, input_file *os.File) (error, bool) {
	if input_file == nil {
		input_file = os.Stdin
	}
	err, exit := SetPassPhrase(wallet_dir, input_file)
	if err != nil {
		return err, exit
	}
	return nil, exit
}

// setPassPhrase generates rsa public and private keys and prompts the user to set a passphrase
// returns an error and bool which if true, the program will exit
func SetPassPhrase(wallet_dir string, input_file *os.File) (error, bool) {
	if input_file == nil {
		input_file = os.Stdin
	}
	rsa_private_key, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return err, true
	}
	if err := rsa_private_key.Validate(); err != nil {
		return err, true
	}
	create_password_msg := fmt.Sprintf("\nCreate a pass phrase for your wallet \"%s\""+PASS_PHRASE_RULES, wallet_dir)
	hashed_password, salt, exit := createPassWord(create_password_msg, wallet_dir, input_file)
	if len(hashed_password) == KEY_LENGTH {
		fmt.Printf(PASS_PHRASE_HASH_SUCCESS)
	} else {
		return fmt.Errorf("Hashed password must be 32 bytes, length was: %v", len(hashed_password)), true
	}
	if exit {
		return nil, exit
	}
	private_key_pem_bytes := exportRsaPrivateKeyAsPemBytes(rsa_private_key)
	if err = encryptAndStore(wallet_dir, input_file, private_key_pem_bytes, hashed_password, salt); err != nil {
		return err, true
	}
	return nil, false
}

// TODO refactor write to file functions consolodate
func writeHashedPassToFile(wallet_dir, filename string, hashed_password []byte, input_file *os.File) error {
	private_key_file_dir := os.Getenv("PRIVATE_KEY_FILE_DIR")
	var file_mode fs.FileMode
	if input_file == nil {
		file_mode = 0444 // what to change this to?
	} else {
		file_mode = 0777
	}
	f := path.Join(private_key_file_dir, wallet_dir, filename)
	if err := os.WriteFile(f, hashed_password, file_mode); err != nil {
		return err
	}
	return nil
}

// writeSaltToFile simply writes salt to file, if a test is running the function then file mode is 777
func writeSaltToFile(wallet_dir, salt_filename string, salt []byte, input_file *os.File) error {
	private_key_file_dir := os.Getenv("PRIVATE_KEY_FILE_DIR")
	var file_mode fs.FileMode
	if input_file == nil {
		file_mode = 0444
	} else {
		file_mode = 0777
	}
	f := path.Join(private_key_file_dir, wallet_dir, salt_filename)
	if err := os.WriteFile(f, salt, file_mode); err != nil {
		return err
	}
	return nil
}

// encryptAndStore encrypts the private key and stores the cipher salt
// and hashed password in the wallet directory
func encryptAndStore(wallet_dir string, input_file *os.File, private_key_bytes, hashed_password, salt []byte) error {
	private_key_file_dir := os.Getenv("PRIVATE_KEY_FILE_DIR")
	cipher_text, err := encryptAES(hashed_password, private_key_bytes)
	if err != nil {
		return err
	}
	fmt.Printf(RSA_ENCRYPTED_SUCCESS)

	if err = writeSaltToFile(wallet_dir, SALT_FILE, salt, input_file); err != nil {
		return err
	}
	salt_file_path := path.Join(private_key_file_dir, wallet_dir, SALT_FILE)
	fmt.Printf(STORED_SUCCESS, "salt", salt_file_path)
	if err = writeHashedPassToFile(wallet_dir, HASHED_PW_FILE, hashed_password, input_file); err != nil {
		return err
	}
	hashed_pw_file_path := path.Join(private_key_file_dir, wallet_dir, HASHED_PW_FILE)
	fmt.Printf(STORED_SUCCESS, "hashed password", hashed_pw_file_path)
	if err = WriteCipherToFile(wallet_dir, CIPHER_FILE, cipher_text, input_file); err != nil {
		return err
	}
	cipher_path := path.Join(private_key_file_dir, wallet_dir, CIPHER_FILE)
	fmt.Printf(STORED_SUCCESS, "encrypted RSA private key", cipher_path)
	fmt.Print("\n")
	return nil
}

// WriteSaltCipherToFile simply writes salt and cipher to file, if a test is running the function then file mode is 777
func WriteCipherToFile(wallet_dir, cipher_text_filename string, cipher []byte, input_file *os.File) error {
	private_key_file_dir := os.Getenv("PRIVATE_KEY_FILE_DIR")
	var file_mode fs.FileMode
	if input_file == nil {
		file_mode = 0444 // what to change this to?
	} else {
		file_mode = 0777
	}
	f := path.Join(private_key_file_dir, wallet_dir, cipher_text_filename)
	if err := os.WriteFile(f, cipher, file_mode); err != nil {
		return err
	}
	return nil
}

// createPassWord gives user a prompt they enter a password which is encrypted with
// pbkdf2 the salt and hashed password are returned if the bool returned is true then the program exits
func createPassWord(prompt, wallet_dir string, input_file *os.File) ([]byte, []byte, bool) {
	if input_file == nil {
		input_file = os.Stdin
	}
	var final_pass_phrase string
	var confirm_failed bool = true
	var pass_phrase1 string = validationLoop(prompt, input_file)
	if pass_phrase1 == EXIT {
		return []byte{}, []byte{}, true
	}
	for confirm_failed {
		if pass_phrase1 == EXIT {
			return []byte{}, []byte{}, true
		}
		pass_phrase2 := getPassPhrase(CONFIRM_PASS_PHRASE, input_file)
		if pass_phrase1 != pass_phrase2 {
			confirm_failed = true
			pass_phrase1 = validationLoop(PASS_PHRASE_MATCH_ERROR, input_file)
		} else {
			confirm_failed = false
			final_pass_phrase = pass_phrase1
		}
	}
	random_salt_bytes, err := generateRandomBytes(SALT_LENGTH)
	if err != nil {
		fmt.Printf("An error occured in generating salt for the password. Error: %v", err)
		return []byte{}, []byte{}, true
	}
	password_hashed_bytes := pbkdf2.Key([]byte(final_pass_phrase), random_salt_bytes, 4096, 32, sha1.New)
	return password_hashed_bytes, random_salt_bytes, false
}

// GenerateRandomBytes generates a []byte of n length
func generateRandomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	if err != nil {
		return nil, err
	}
	return b, nil
}

func exportRsaPublicKeyAsPemBytes(public_key *rsa.PublicKey) []byte {
	pub_key_bytes := x509.MarshalPKCS1PublicKey(public_key)
	pub_key_pem := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PUBLIC KEY",
			Bytes: pub_key_bytes,
		},
	)
	return pub_key_pem
}

func exportRsaPrivateKeyAsPemBytes(private_key *rsa.PrivateKey) []byte {
	private_key_bytes := x509.MarshalPKCS1PrivateKey(private_key)
	private_key_pem := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: private_key_bytes,
		},
	)
	return private_key_pem
}

// validationLoop validates user input for pass phrase, if it's not
// proper then the loop updates the prompt requesting a stronger
// pass phrase and continues to ask for and check user input until valid
// User may blow out of the program and setting a pass phrase by typing 'e' [e]xit
func validationLoop(prompt string, input_file *os.File) (pass_phrase1 string) {
	var try_again bool = true
	for try_again {
		pass_phrase1 = getPassPhrase(prompt, input_file)
		if pass_phrase1 == EXIT {
			try_again = false
		} else {
			if !validate(pass_phrase1) {
				try_again = true
				if pass_phrase1 == SPACE_ERROR {
					prompt = PASS_PHRASE_SPACE_ERROR
				} else {
					new_prompt := fmt.Sprintf("\nPlease create a stronger pass phrase.\n\nThe length of your pass phrase was %v. "+PASS_PHRASE_RULES, len(pass_phrase1))
					prompt = new_prompt
				}
			} else {
				try_again = false
			}
		}
	}
	return
}

// validate ensures the user selects a password that is alpha numeric,
// can contain special characters and is between 8 and 32 characters long
func validate(pass_phrase string) bool {
	re := regexp.MustCompile(`^[:-@!-/A-Za-z0-9-]{8,32}$`)
	return re.MatchString(pass_phrase)
}

// getPassPhrase provides a prompt and takes (hidden) user input
func getPassPhrase(prompt string, input_file *os.File) (pass_phrase string) {
	var err error
	fmt.Print(prompt)
	fmt.Print("\033[8m")
	if os.Getenv("PROD") == "true" {
		reader := bufio.NewReader(os.Stdin)
		pass_phrase, _ = reader.ReadString('\n')
		pass_phrase = strings.TrimSuffix(pass_phrase, "\n")
		pass_phrase_no_spaces := strings.ReplaceAll(pass_phrase, " ", "")
		if pass_phrase_no_spaces != pass_phrase {
			pass_phrase = SPACE_ERROR
		}
	} else {
		_, err = fmt.Fscanf(input_file, "%s", &pass_phrase) // needs to be tested
	}
	fmt.Print("\033[28m")
	if err != nil {
		fmt.Printf("User input error: %v", err)
		return ""
	}
	return
}

// encryptAES encrypts a string with a key - a 32 byte hashed pass phrase
func encryptAES(key, pem_bytes_to_encryp []byte) ([]byte, error) {
	if len(key) != KEY_LENGTH {
		err := fmt.Sprintf("Key length should be 32 bytes. Passed key length was: %v\n. KEY_LENGTH const should not be changed from 32, KEY_LENGTH const was: %v.", len(key), KEY_LENGTH)
		return []byte{}, errors.New(err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		fmt.Printf("Error occured while encrypting the private key, aes.NewCipher() function error: %v", err)
		return []byte{}, err
	}
	aes_GCM, err := cipher.NewGCM(block)
	if err != nil {
		fmt.Printf("Error occured while encrypting the private key, cipher.NewGCM() function error: %v", err)
		return []byte{}, err
	}
	nonce := make([]byte, aes_GCM.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil { // melvinvivas.com adds this line, is it needed?
		fmt.Printf("Error occured while encrypting the private key, io.ReadFull(rand.Reader, nonce) function error: %v", err)
		return []byte{}, err
	}
	cipher_text_bytes := aes_GCM.Seal(nonce, nonce, pem_bytes_to_encryp, nil)
	// string_cipher_text := fmt.Sprintf("%x", cipher_text)
	return cipher_text_bytes, nil
}
