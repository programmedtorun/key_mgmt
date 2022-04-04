/*
  encrypt.go sets the user's password by calling InitCipherAndPassword(), the user's password
  is salted and hashed using pbkdf2, the key is then used to encrypt a wallet's private key
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
	PASSWORD_HASH_SUCCESS = "\nSUCCESS!! Your password has been hashed."
	RSA_ENCRYPTED_SUCCESS = "\nSUCCESS!! Your RSA Private Key has been encrypted."
	PASSWORD_MATCH_ERROR  = "\nPasswords do not match please try again. Enter a password.\n> "
	PASSWORD_SPACE_ERROR  = "\nYou entered a space in you password. Please enter a new password.\n> "
	HASHED_PW_DESCRIPTOR  = "hashed password"
	CIPHER_DESCRIPTOR     = "encrypted RSA private key"
	CONFIRM_PASSWORD      = "\nType your password again, to confirm selection.\n> "
	SALT_DESCRIPTOR       = "salt data"
	PASSWORD_RULES        = "Your password must be:\n-> Alphanumeric, uppercase letters OK\n-> Free of spaces\n-> Between 8 - 32 characters\n-> Special characters OK\n-> Type 'e' and hit return to exit this process\n\nEnter your new password.\n> "
	STORED_SUCCESS        = "\nSUCCESS!! Your %s has been stored in the file: \n%s"
	HASHED_PW_FILE        = "hashed_pw.dat"
	CIPHER_FILE           = "cipher.dat"
	SALT_FILE             = "salt.dat"
)

// InitCipherAndPassword initiates the password process
func InitCipherAndPassword(wallet_dir string, input_file *os.File) (error, bool) {
	if input_file == nil {
		input_file = os.Stdin
	}
	err, exit := SetPassword(wallet_dir, input_file)
	if err != nil {
		return err, exit
	}
	return nil, exit
}

// SetPassword generates rsa public and private keys and prompts the user to set a password
// returns an error and bool which if true, the program will exit
func SetPassword(wallet_dir string, input_file *os.File) (error, bool) {
	if input_file == nil {
		input_file = os.Stdin
	}

	rsa_private_key, err := generateRSA()
	if err != nil {
		return err, true
	}

	create_password_msg := fmt.Sprintf("\nCreate a password for your wallet \"%s\" "+PASSWORD_RULES, wallet_dir)
	hashed_password, salt, exit := createPassWord(create_password_msg, wallet_dir, input_file)
	if exit {
		return nil, exit
	}
	if len(hashed_password) == KEY_LENGTH {
		fmt.Printf(PASSWORD_HASH_SUCCESS)
	} else {
		return fmt.Errorf("Hashed password must be 32 bytes, length was: %v", len(hashed_password)), true
	}

	private_key_pem_bytes := exportRsaPrivateKeyAsPemBytes(rsa_private_key)
	cipher_text, err := encryptAES(hashed_password, private_key_pem_bytes)
	if err != nil {
		return err, true
	} else {
		fmt.Printf(RSA_ENCRYPTED_SUCCESS)
	}

	if err = writeAllData(wallet_dir, input_file, salt, hashed_password, cipher_text); err != nil {
		return err, true
	}

	return nil, false
}

func generateRSA() (*rsa.PrivateKey, error) {
	rsa_private_key, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return nil, err
	}
	if err := rsa_private_key.Validate(); err != nil {
		return nil, err
	}
	return rsa_private_key, nil
}

// createPassWord gives user a prompt they enter a password which is salted and encrypted with
// pbkdf2. The salt and hashed password are returned. If the bool returned is true then the program exits
func createPassWord(prompt, wallet_dir string, input_file *os.File) ([]byte, []byte, bool) {
	if input_file == nil {
		input_file = os.Stdin
	}

	final_password := passwordConfirmLoop(prompt, wallet_dir, input_file)
	if final_password == EXIT {
		return []byte{}, []byte{}, true
	}

	rand_salt_bytes, err := generateRandomBytes(SALT_LENGTH)
	if err != nil {
		fmt.Printf("An error occured in generating salt for the password. Error: %v", err)
		return []byte{}, []byte{}, true
	}
	password_hashed_bytes := pbkdf2.Key([]byte(final_password), rand_salt_bytes, 4096, 32, sha1.New)
	return password_hashed_bytes, rand_salt_bytes, false
}

// passwordConfirmLoop asks the user to type their chosen password in a 2nd time, for verification
func passwordConfirmLoop(prompt, wallet_dir string, input_file *os.File) string {
	var final_password string
	var confirm_failed bool = true
	var password_first_entry string = validationLoop(prompt, input_file)
	if password_first_entry == EXIT {
		return EXIT
	}
	for confirm_failed {
		if password_first_entry == EXIT {
			return EXIT
		}
		password_second_entry := getPassword(CONFIRM_PASSWORD, input_file)
		if password_first_entry != password_second_entry {
			confirm_failed = true
			password_first_entry = validationLoop(PASSWORD_MATCH_ERROR, input_file)
		} else {
			confirm_failed = false
			final_password = password_first_entry
		}
	}
	return final_password
}

// validationLoop validates user input in password creation, if it's not
// proper then the loop updates the prompt requesting a stronger
// password. validationLoop continues to ask for and check user input until valid.
// User may blow out of the program instead of setting a password by typing 'e' [e]xit
func validationLoop(prompt string, input_file *os.File) (password string) {
	var try_again bool = true
	for try_again {
		password = getPassword(prompt, input_file)
		if password == EXIT {
			try_again = false
		} else {
			if !validate(password) {
				try_again = true
				if password == SPACE_ERROR {
					prompt = PASSWORD_SPACE_ERROR
				} else {
					new_prompt := fmt.Sprintf("\nPlease create a stronger password.\n\nThe length of your password was %v. "+PASSWORD_RULES, len(password))
					prompt = new_prompt
				}
			} else {
				try_again = false
			}
		}
	}
	return
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

// validate ensures the user selects a password that is alpha numeric,
// can contain special characters and is between 8 and 32 characters long
func validate(password string) bool {
	re := regexp.MustCompile(`^[:-@!-/A-Za-z0-9-]{8,32}$`)
	return re.MatchString(password)
}

// getPassword provides a prompt and takes (hidden) user input
func getPassword(prompt string, input_file *os.File) (password string) {
	var err error
	fmt.Print(prompt)
	fmt.Print("\033[8m")
	if os.Getenv("PROD") == "true" {
		reader := bufio.NewReader(os.Stdin)
		password, _ = reader.ReadString('\n')
		password = strings.TrimSuffix(password, "\n")
		password_no_spaces := strings.ReplaceAll(password, " ", "")
		if password_no_spaces != password {
			password = SPACE_ERROR
		}
	} else {
		_, err = fmt.Fscanf(input_file, "%s", &password) // needs to be tested
	}
	fmt.Print("\033[28m")
	if err != nil {
		fmt.Printf("User input error: %v", err)
		return ""
	}
	return
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

// writeAllData stores the cipher, salt, and hashed password in the wallet directory
func writeAllData(wallet_dir string, input_file *os.File, salt, hashed_password, cipher_text []byte) error {
	private_key_file_dir := os.Getenv("PRIVATE_KEY_FILE_DIR")
	file_names := []string{SALT_FILE, HASHED_PW_FILE, CIPHER_FILE}
	file_name_descriptors := []string{SALT_DESCRIPTOR, HASHED_PW_DESCRIPTOR, CIPHER_DESCRIPTOR}
	data_slice := [][]byte{}
	data_slice = append(data_slice, salt)
	data_slice = append(data_slice, hashed_password)
	data_slice = append(data_slice, cipher_text)
	for idx, file_name := range file_names {
		if err := writeData(wallet_dir, file_name, data_slice[idx], input_file); err != nil {
			return err
		}
		file_path := path.Join(private_key_file_dir, wallet_dir, file_name)
		fmt.Printf(STORED_SUCCESS, file_name_descriptors[idx], file_path)
	}
	fmt.Print("\n")
	return nil
}

// encryptAES encrypts a string with a key - a 32 byte hashed password
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

func writeData(wallet_dir, filename string, data []byte, input_file *os.File) error {
	private_key_file_dir := os.Getenv("PRIVATE_KEY_FILE_DIR")
	var file_mode fs.FileMode
	if input_file == nil {
		file_mode = 0600
	} else {
		file_mode = 0777
	}
	f := path.Join(private_key_file_dir, wallet_dir, filename)
	if err := os.WriteFile(f, data, file_mode); err != nil {
		return err
	}
	return nil
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
