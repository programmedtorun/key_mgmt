/*
This file runs the main program loop which finds wallets, analyzes and
launches files for minting, creates wallets, presents confirmation
messages and initiates the minting process
*/

package cli

import (
	"bufio"
	"fmt"
	"io/fs"
	"log"
	"os"
	"time"

	"github.com/programmedtorun/key_mgmt/mint"
	"github.com/programmedtorun/key_mgmt/wallet"
)

var wallet_dir string
var exit bool
var new_file bool
var main_loop bool = true

const (
	WELCOME_PARAGRAPH = "This program will allow you to create a wallet, which is simply \na directory containing a private key file to be used for minting \nKAON. The program looks in the private_key directory for wallet \ndirectories on your machine. The program will allow you to \nselect a wallet and begin the minting process, you may also \ncreate new wallets to use for minting."
	WALLET_FILES_MSG  = "\nFound wallets in the key_mgmt/private_key directory, listed here:\n\n"
	ONE_DIR_MSG       = "\nFound 1 wallet directory:"
	INIT_MSG          = "\n\nNo wallet directories detected. Would you like to create one? Select 'y' or 'n'\n> "
)

func Run() {
	printWelcome()
	fmt.Println(WELCOME_PARAGRAPH)
	for main_loop {
		main_loop = false
		dirs, err := wallet.PrivateKeyFileDirRead(os.Getenv("PRIVATE_KEY_FILE_DIR"))
		if err != nil {
			fmt.Println(err)
		}
		wallet_dir, exit = analyzeDirs(dirs)
		if !exit {
			wallet.Divider()
			mint_confirmation, wallet_dir_to_mint, err := wallet.MintConfirmation(wallet_dir, nil)
			if err != nil {
				fmt.Println(err)
			}
			if wallet_dir_to_mint == wallet.LIST_FILES {
				main_loop = true // if user selected [l]ist files, then start the loop over again
			} else if mint_confirmation && (wallet_dir_to_mint != wallet.LIST_FILES) {
				can := wallet.SetupMint(wallet_dir_to_mint, nil) // User must re-enter their password to mint
				if can != nil {
					mint.Mint(can)
				}
			}
		}
	}
	printExit()
}

func analyzeDirs(dirs []fs.FileInfo) (wallet_dir string, exit bool) {
	var err error
	printFoundDirs(dirs)
	if len(dirs) == 1 {
		wallet_dir = dirs[0].Name()
		wallet_dir, new_file = wallet.OneDirOptions(dirs, nil, wallet.ONE_DIR_MSG, wallet_dir, true)
	} else if len(dirs) > 1 {
		wallet_dir, new_file = wallet.UserSelectDir(dirs, nil, wallet.FILE_SELECTION_MSG, "", false)
	} else {
		wallet_dir, new_file = wallet.CreateFirstWalletOfProgram(INIT_MSG, nil)
	}
	if wallet_dir == "" {
		exit = true
	}
	if new_file && wallet_dir != "" {
		wallet.WalletCreationMsg(wallet_dir)
		err, exit = wallet.InitCipherAndPassword(wallet_dir, nil)
		if err != nil {
			fmt.Println(err)
		}
	}
	return
}

func printFoundDirs(dirs []fs.FileInfo) {
	dir_count := len(dirs)
	if dir_count == 1 {
		fmt.Println(ONE_DIR_MSG, dirs[0].Name())
	} else if dir_count > 1 {
		fmt.Print(WALLET_FILES_MSG)
		for idx, dir := range dirs {
			fmt.Println(idx+1, "--", dir.Name())
		}
	}
	wallet.Divider()
}

func printWelcome() {
	file, err := os.Open("welcome.txt")
	if err != nil {
		log.Fatalf("failed to open")
	}
	scanner := bufio.NewScanner(file)
	scanner.Split(bufio.ScanLines)
	var text []string
	for scanner.Scan() {
		text = append(text, scanner.Text())
	}
	file.Close()
	for _, each_ln := range text {
		time.Sleep(45 * time.Millisecond)
		fmt.Println(each_ln)
	}
}

func printExit() {
	fmt.Println("Exiting program.")
}
