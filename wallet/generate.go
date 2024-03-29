/*
  generate.go generates a wallet for the user, initiates encryption and the
  minting process either with the generated wallet, or via prompting the user
  to select an existing wallet
*/

package wallet

import (
	"bufio"
	"fmt"
	"io/fs"
	"io/ioutil"
	"log"
	"os"
	"path"
	"regexp"
	"strconv"
	"strings"

	"github.com/programmedtorun/key_mgmt/candidate"
	"golang.org/x/crypto/ssh/terminal"
)

const (
	FILE_NAME_VALIDATION_MSG = "\nPlease choose a better wallet name.\n\nCreate a name that is:\n-> Alphanumeric\n-> Between 3 - 32 characters\n-> Characters '.', '-' and '_' are OK\n-> Type 'e' and hit return to exit this process\n\nEnter your new wallet name.\n> "
	FILE_SELECTION_RETRY_MSG = "\nSelection not recognized. Please carefully select a number from the list corrisponding to a wallet. "
	FILE_NAME_CREATION_MSG   = "\nPlease create a simple name for your new KAON wallet. Wallet\nname chosen must be unique to the wallet list in the \nkey_mgmt/private_key directory. Type 'e' to exit.\n\nEnter your new wallet name.\n> "
	FILE_NAME_SPACE_ERROR    = "\nYou entered a space in you wallet name. Please choose a new wallet name.\n> "
	CREATE_NEW_WALLET_MSG    = "\nDo you wish to create a new wallet? Type 'y' to create, or any key to exit.\n> "
	PASSWORD_EXPLANATION     = "\nNow you must create a password for your wallet, this will \nallow access to an RSA public and private key pair, \nsubsequently encrypt your private key and write the encrypted \nprivate key to a 'cipher.dat' file.\n\nNow generating your RSA public and private key pair using \nRSA-4096 bit encryption, this may take just a moment..."
	PRIVATE_KEY_FILE_DIR     = "./private_key"
	FILE_NAME_EXISTS_MSG     = "\nThat name already exists within the key_mgmt/private_key \ndirectory, name must be unique.\n\nPlease enter a simple name. Type 'e' to exit.\n> "
	CONFIRM_MINT_WALLET      = "OK! let's get started on minting KAON!! Meant to mint ;). \nIs \"%s\" the wallet you wish to use to mint?\n\nOptions:\n-> Type 'y' for yes.\n-> Type 'n' to create a new wallet or exit.\n-> Type 'l' to list wallet(s) - back to program start.\n-> Type 'e' or any key to exit.\n> "
	SELECT_DIR_RETRIES       = 4
	FILE_SELECTION_MSG       = "Options:\n-> Type the NUMBER of the wallet you wish to use to mint KAON.\n-> Type 'c' to create a NEW wallet.\n-> Type 'cp' to change your password.\n-> Type 'e' to exit.\n> "
	CHANGE_PASS_PROMPT       = "\nSelect the NUMBER of the wallet for which you'd like to change \nthe password. After your selection, you will be prompted to \nenter your existing password.\n> "
	START_MINTING_MSG        = "Do you wish to start the minting process with \"%s\"? \nNote you will be prompted again for the wallet password.\n-> Type 'y' to mint.\n-> Type 'l' to list wallet(s) - back to program start.\n-> Type any key to exit.\n> "
	CHANGE_PASSWORD          = "cp"
	USER_INPUT_ERR           = "An error occured obtaining user input please try again.\n"
	ONE_DIR_MSG              = "Options:\n-> Type 'm'  to continue to confirm mint with this wallet.\n-> Type 'cp' to change your password.\n-> Type 'c'  to create a NEW wallet.\n-> Type 'e'  to exit.\n> "
	SALT_LENGTH              = 8 // Can be changed. Suggest SALT_LENGTH be 32 or under
	SPACE_ERROR              = "se"
	KEY_LENGTH               = 32 // Should never be changed. Must be 32.
	LIST_FILES               = "l"
	MANY_TRIES               = "tries"
	ONE_TRY                  = "try"
	CREATE                   = "c"
	EXIT                     = "e"
	MINT                     = "m"
	YES                      = "y"
	NO                       = "n"
)

// TODO fix directory varables (will fix when tests are fixed)
func init() {
	if _, err := os.Stat(PRIVATE_KEY_FILE_DIR); os.IsNotExist(err) {
		err := os.Mkdir(PRIVATE_KEY_FILE_DIR, 0777)
		if err != nil {
			log.Fatal()
		}
	}
	os.Setenv("PRIVATE_KEY_FILE_DIR", PRIVATE_KEY_FILE_DIR)
	os.Setenv("FILE_PREFIX", "")
	os.Setenv("PROD", "true")
}

// privateKeyFileDirRead reads the private_key_file_dir and returns wallet list; FileInfo objects
func PrivateKeyFileDirRead(private_key_file_dir string) ([]fs.FileInfo, error) {
	files, err := ioutil.ReadDir(private_key_file_dir)
	if err != nil {
		fmt.Println("Error reading private_key_file directory:", err)
		return nil, err
	}
	return files, nil
}

// OneDirOptions wraps UserSelectDir(), single dir parameters, name -> one_file string and name -> single_file bool
func OneDirOptions(dirs []fs.FileInfo, input_file *os.File, selection_prompt, dirname string, single_file bool) (private_key_filename string, new_file bool) {
	private_key_filename, new_file = UserSelectDir(dirs, nil, selection_prompt, dirname, true)
	return
}

// UserSelectFile allows the user select a file based on files in a dir
// returns the file name as a string, if it's a newly created file the
// bool variable new_file returns true, else new_file is false
func UserSelectDir(dirs []fs.FileInfo, input_file *os.File, selection_prompt, one_dir string, single_dir bool) (selected_dir string, new_file bool) {
	if input_file == nil {
		input_file = os.Stdin
	}
	var dir_slice, err, dir_number_str, tries, continue_loop = setupUserSelectDir(dirs, selection_prompt, input_file)
	for continue_loop {
		switch dir_number_str {
		case MINT:
			return caseMint(single_dir, one_dir, selected_dir, new_file)
		case CREATE:
			new_file = true
			return CreateWallet(input_file, FILE_NAME_CREATION_MSG), new_file // user wants to create a new file vs. select from file list
		case EXIT:
			return
		case CHANGE_PASSWORD:
			return caseChangePassword(single_dir, one_dir, CHANGE_PASS_PROMPT, input_file, dir_slice)
		default:
			selected_dir, dir_number_str, new_file, tries, continue_loop = defaultCase(dir_number_str, MANY_TRIES, dir_slice, tries, err, input_file)
		}
	}
	return
}

// setupUserSelectFile simply initializes variables, including user input - file number
func setupUserSelectDir(dirs []fs.FileInfo, selection_prompt string, input_file *os.File) (dir_slice []string, err error, dir_number_str string, tries int, continue_loop bool) {
	tries = SELECT_DIR_RETRIES
	continue_loop = true
	dir_slice = []string{}
	for idx, _ := range dirs {
		dir_slice = append(dir_slice, dirs[idx].Name())
	}
	dir_number_str, err = getUserAnswer(selection_prompt, "", input_file)
	if err != nil {
		fmt.Printf("Error: %x", err)
		dir_number_str = ""
		return
	}
	return
}

// CreateWallet prompts the user to create a unique wallet name, if not unique, CreateWallet is called
// recursively until a unique file name or user input of [e]xit is given.
func CreateWallet(input_file *os.File, creation_msg string) (wallet_dir string) {
	var err error
	var already_exists bool
	existing_dirs, err := PrivateKeyFileDirRead(os.Getenv("PRIVATE_KEY_FILE_DIR")) // check if there are files
	if err != nil {
		log.Printf("Error is: %x", err)
	}
	wallet_dir, err = walletValidationLoop(creation_msg, input_file)
	if err != nil {
		return fmt.Sprintf("%x", err)
	}
	if wallet_dir == EXIT {
		return ""
	}
	if len(existing_dirs) != 0 {
		for _, dir := range existing_dirs {
			if wallet_dir == dir.Name() {
				already_exists = true
			}
		}
	}
	if already_exists {
		return CreateWallet(input_file, FILE_NAME_EXISTS_MSG)
	}
	private_key_file_dir := os.Getenv("PRIVATE_KEY_FILE_DIR")
	p := path.Join(private_key_file_dir, wallet_dir)
	err = os.Mkdir(p, 0700)
	if err != nil {
		log.Fatal(err)
		return ""
	}
	return
}

// caseMint runs if the MINT case is hit i.e. one file exists and the user types 'm' to immidiately confirm mint
func caseMint(single_dir_arg bool, one_file_arg string, selected_dir_arg string, new_dir_arg bool) (string, bool) {
	if single_dir_arg {
		return one_file_arg, false
	} else {
		return selected_dir_arg, new_dir_arg
	}
}

// caseChangePassword runs if the CHANGE_PASSWORD switch statement is hit in UserSelectFile()
func caseChangePassword(single_file bool, one_file, prompt string, input_file *os.File, file_slice []string) (selected_file string, new_file bool) {
	// cp suffix stands for [c]hange [p]assword
	if !single_file {
		file_number_str_cp, err := getUserAnswer(prompt, "", input_file)
		if err != nil {
			fmt.Printf("Error: %x", err)
			return
		}
		// NR - *Note* when a wallet file has stashes or stash references, to change a password the stashes will have to be moved to the new file with the new password
		file_to_cp := obtainFile(file_number_str_cp, file_slice)
		_, found := inSlice(file_slice, file_to_cp)
		if found && file_to_cp != "" {
			return changePassword(file_to_cp, input_file), false
		} else {
			return
		}
	} else {
		return changePassword(one_file, input_file), false
	}
}

// obtainFile returns the file the user selects from the private key file directory
func obtainFile(file_number_str string, file_slice []string) (selected_file string) {
	file_number_int, _ := strconv.Atoi(file_number_str) // will be 0 if file_number_str is garbage
	if file_number_int == 0 {
		return
	}
	if file_number_int > len(file_slice) {
		fmt.Printf("That number selection: %v, does not corrispond to a wallet.\n", file_number_int)
		return
	}
	selected_file = file_slice[file_number_int-1]
	fmt.Printf("User selected wallet: %s \n", selected_file)
	return
}

// inSlice verifies that a string file name is in a slice
func inSlice(slice []string, file_name string) (int, bool) {
	for i, item := range slice {
		if item == file_name {
			return i, true
		}
	}
	return -1, false
}

// changePassword prompts the user to put in their current password, verifies this
// and then clears the existing file and has the user create initiate the password process with SetPassword()
func changePassword(wallet_dir string, input_file *os.File) (fresh_wallet_dir string) {
	if GetPublicKey(wallet_dir, input_file) != nil {
		fresh_wallet_dir = clearFiles(wallet_dir) // file is removed but name stays the same
		if fresh_wallet_dir == "" {
			return
		} else {
			err, exit := SetPassword(fresh_wallet_dir, input_file)
			if err != nil {
				fmt.Printf("Encountered a problem resetting the password on wallet %s, error: %v\n", fresh_wallet_dir, err)
				return ""
			}
			if exit {
				return ""
			}
			return
		}
	} else {
		return
	}
}

// clearFiles removes the files from the wallet dir
// Note distructive! But if the user changes their password this creates a new key anyway, so the encrypted private key will be different
// Note - if the user blows out of the program using [e]xit while changing their password the file name is gone
// Note - again when a wallet file has stashes or stash references, to change a password the stashes will have to be transferred to the new file with the new password
func clearFiles(wallet_dir string) string {
	private_key_file_dir := os.Getenv("PRIVATE_KEY_FILE_DIR")
	directory := path.Join(private_key_file_dir, wallet_dir)
	dir_read, _ := os.Open(directory)
	dir_files, _ := dir_read.Readdir(0)
	for index := range dir_files {
		f := dir_files[index]
		file_name := f.Name()
		full_path := path.Join(directory, file_name)
		os.Remove(full_path)
		fmt.Printf("removing file: %s\n", full_path)
	}
	return wallet_dir
}

// defaultCase runs if the default: is hit in the UserSelectFile() switch statement,
// defaultCase gives the user 3 tries properly select a file
func defaultCase(file_num_str_arg, chances string, file_slice []string, tries_arg int, err error, input_file *os.File) (selected_file, file_number_str string, new_file bool, tries int, continue_loop bool) {
	selected_file = obtainFile(file_num_str_arg, file_slice)
	if selected_file == "" {
		if tries_arg == 1 {
			tries = 1
			file_number_str = file_num_str_arg
			continue_loop = false
			return
		} else {
			tries_arg--
			continue_loop = true
			if tries_arg == 1 {
				chances = ONE_TRY
			}
			tries = tries_arg
			mid := fmt.Sprintf("%v %s left before the program terminates.\n", tries, chances)
			prompt := FILE_SELECTION_RETRY_MSG + mid + FILE_SELECTION_MSG
			file_number_str, err = getUserAnswer(prompt, "", input_file)
			if err != nil {
				fmt.Printf("Error: %x", err)
			}
		}
	} else {
		continue_loop = false
		file_number_str = file_num_str_arg
		tries = tries_arg
		return
	}
	return
}

// CreateFirstWalletOfProgram runs if there are no files in the private key file directory
func CreateFirstWalletOfProgram(prompt string, input_file *os.File) (wallet_dir string, new_file bool) {
	if input_file == nil {
		input_file = os.Stdin
	}
	create_wallet, err := getUserAnswer(prompt, "", input_file)
	if err != nil {
		fmt.Printf("Error is: %x", err)
		return
	}
	if create_wallet == YES {
		wallet_dir = CreateWallet(input_file, FILE_NAME_CREATION_MSG)
		new_file = true
	} else {
		return
	}
	return
}

// getUserAnswer gives the user a prompt and takes user input
func getUserAnswer(prompt, priv_key_filename string, input_file *os.File) (string, error) {
	var answer string
	if priv_key_filename == "" {
		fmt.Printf(prompt)
	} else {
		fmt.Printf(prompt, priv_key_filename)
	}
	_, err := fmt.Fscanf(input_file, "%s", &answer)
	if err != nil {
		fmt.Printf("User input error: %v\n", err)
		return "", err
	}
	return answer, nil
}

// walletValidationLoop takes user input and makes sure it conforms to naming conventions in validateAlphaNum()
func walletValidationLoop(prompt string, input_file *os.File) (wallet_dir string, err error) {
	var try_again bool = true
	for try_again {
		wallet_dir, err = getWalletName(prompt, input_file)
		if wallet_dir == EXIT {
			try_again = false
		}
		if !validateAlphaNum(wallet_dir) {
			try_again = true
			if wallet_dir == SPACE_ERROR {
				prompt = FILE_NAME_SPACE_ERROR
			} else {
				prompt = FILE_NAME_VALIDATION_MSG
			}
		} else {
			try_again = false
		}
	}
	return
}

// getWalletName reads from stdin and flags if there is a space in the name
// Note, this function is similar to getPassword() in encrypt.go, maybe refactor
func getWalletName(prompt string, input_file *os.File) (private_key_filename string, err error) {
	fmt.Printf(prompt)
	if os.Getenv("PROD") == "true" {
		reader := bufio.NewReader(os.Stdin)
		private_key_filename, _ = reader.ReadString('\n')
		private_key_filename = strings.TrimSuffix(private_key_filename, "\n")
		private_key_filename_no_spaces := strings.ReplaceAll(private_key_filename, " ", "")
		if private_key_filename_no_spaces != private_key_filename {
			private_key_filename = SPACE_ERROR
		}
	} else {
		_, err = fmt.Fscanf(input_file, "%s", &private_key_filename) // needs to be tested
	}
	if err != nil {
		fmt.Printf("Input error: %v", err)
		return
	}
	return
}

// validateAlphaNum ensures the filename string is alphanumeric, between 3 - 32 characters
// filename can also contain characters '.', '-', '_' but doesn't have to.
func validateAlphaNum(private_key_filename string) bool {
	re := regexp.MustCompile(`^[A-Za-z0-9-._]{3,32}$`)
	if private_key_filename == EXIT {
		return true
	} else {
		return re.MatchString(private_key_filename)
	}
}

// MintConfirmation walks the user through wallet creation / use, if a new wallet is created
// password creation is initiated. Finally MintConfirmation confirms user mint choice.
func MintConfirmation(wallet_dir string, input_file *os.File) (bool, string, error) {
	if input_file == nil {
		input_file = os.Stdin
	}
	mint_answer, err := getUserAnswer(CONFIRM_MINT_WALLET, wallet_dir, input_file)
	if err != nil {
		return false, "", err
	}
	if mint_answer == YES {
		return true, wallet_dir, nil
	} else if mint_answer == NO {
		new_wallet_answer, err := getUserAnswer(CREATE_NEW_WALLET_MSG, "", input_file)
		if err != nil {
			return false, "", err
		}
		if new_wallet_answer == YES {
			var wallet_next string = CreateWallet(input_file, FILE_NAME_CREATION_MSG)
			WalletCreationMsg(wallet_next)
			err, exit := InitCipherAndPassword(wallet_next, input_file)
			if err != nil || exit == true {
				return false, "", err
			}
			return userConfirmMint(wallet_next, input_file)
		} else {
			return false, "", nil
		}
	} else if mint_answer == LIST_FILES {
		return false, LIST_FILES, nil
	}
	return false, "", nil
}

// userConfirmMint asks if the user wants to start minting Kaon. Password will need to be re-entered if so.
func userConfirmMint(private_key_filename_next string, input_file *os.File) (bool, string, error) {
	if input_file == nil {
		input_file = os.Stdin
	}
	start_mint_answer, err := getUserAnswer(START_MINTING_MSG, private_key_filename_next, input_file)
	if err != nil {
		return false, "", err
	}
	if start_mint_answer == YES {
		return true, private_key_filename_next, nil
	} else if start_mint_answer == LIST_FILES {
		return false, LIST_FILES, nil
	}
	return false, "", nil
}

// setupMint returns *Candidate given user provides the correct password
func SetupMint(wallet_dir string, input_file *os.File) *candidate.Candidate {
	rsa_public_key := GetPublicKey(wallet_dir, input_file)
	if rsa_public_key != nil {
		return candidate.New(rsa_public_key, "")
	} else {
		return nil
	}
}

// devider prints a star '*' divider
func Divider() {
	if os.Getenv("PROD") == "true" {
		width, height, err := terminal.GetSize(int(os.Stdin.Fd()))
		if err != nil {
			fmt.Printf("Termainl height + width retrieval problem. Height: %v, Width: %v, error: %v", height, width, err)
		}
		divider := fmt.Sprintf("\n" + strings.Repeat("*", width))
		fmt.Println(divider)
	} else {
		fmt.Println("\n" + strings.Repeat("*", 70)) // Getting width in test throws an error, so printing constant.
	}
}

func WalletCreationMsg(wallet_dir string) {
	fmt.Printf("\nSUCCESS!! Your new wallet name is: %s\n", wallet_dir)
	fmt.Println(PASSWORD_EXPLANATION)
}
