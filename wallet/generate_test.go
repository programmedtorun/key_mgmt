/*

 */

package wallet

import (
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"strconv"
	"testing"

	"github.com/programmedtorun/key_mgmt/mint"
)

const (
	TEST_PASS_PHRASE = "hiImaPassPhrase123!"
	T_KEY_LENGTH     = 32
	PK_TEST_FILE     = "ztemp.txt" // A private key test file string
	ENTER            = "\n"
	ZERO             = "0"
)

var private_key_filename string
var exit bool
var test_sep []byte
var color_reset string
var green string
var red string
var fail bool
var fail_count int
var pass_count int
var test_slice []byte
var fail_list []string

// something's going on with tearDownTests(), causing periodic failures, maybe..
// Also randomly I'll get invalid key size for AES (shorter than 32), don't know
// why this is happening
func TestMain(m *testing.M) {
	setupTests()
	exit_code := m.Run()
	tearDownTests()
	fmt.Printf("Test Exit code: %v\n", exit_code)
	os.Exit(exit_code)
}

func tearDownTests() {
	private_key_file_dir := os.Getenv("PRIVATE_KEY_FILE_DIR")
	os.RemoveAll(private_key_file_dir) //*should remove temp dirs and contents..
	os.Unsetenv("PRIVATE_KEY_FILE_DIR")
	os.Unsetenv("FILE_PREFIX")
	fmt.Println(string(color_reset))
	var failures string
	var passes string
	var all_pass string
	if fail_count == 0 {
		all_pass = "ALL "
	} else {
		all_pass = ""
		failures = fmt.Sprintf("%d   FAILED TESTS:\n", fail_count)
		fmt.Println(string(red), failures, string(color_reset))
		for idx, failed_test := range fail_list {
			test_num := fmt.Sprintf("%v", idx+1)
			fmt.Println(string(red), test_num+". "+failed_test, string(color_reset))
		}
	}
	passes = fmt.Sprintf("%s%d TESTS PASSED.", all_pass, pass_count)
	fmt.Println(string(green), passes, string(color_reset))

}
func setupTests() {
	test_slice = []byte("Hi I'm a test slice")
	color_reset = "\033[0m"
	green = "\033[32m"
	red = "\033[31m"
	fmt.Println(string(color_reset))
	test_sep = []byte(",")
	os.Setenv("PROD", "false")
	os.Setenv("FILE_PREFIX", "test_auto_gen_file_")                               // TODO don't think this is needed
	dir, err := os.MkdirTemp("./../private_key_file_dir", "test_auto_generation") // TODO don't do this use a temp dir in wallet/
	if err != nil {
		fmt.Printf("Error creating temp dir: %v\n", err)
	}
	os.Setenv("PRIVATE_KEY_FILE_DIR", dir) // TODO need to fix the directory stuff
	os.Setenv("PRIVATE_KEY_FILE_DIR_BASE", "./../private_key_file_dir")

}

// TestEncryptAndDecryptAES() is a test most applicable when the private key file dir contains wallet files
func TestEncryptAndDecryptAES(t *testing.T) {
	fail = false
	files, err := PrivateKeyFileDirRead(os.Getenv("PRIVATE_KEY_FILE_DIR_BASE"))
	if err != nil {
		fail = true
		t.Errorf("Encountered a problem opening the private key file dir: %v", err)
	}
	if len(files) > 1 {
		new_file_scenario := "1" + ENTER + NO + ENTER + YES + ENTER +
			TEST_PASS_PHRASE + ENTER + YES + ENTER +
			TEST_PASS_PHRASE + ENTER + TEST_PASS_PHRASE + ENTER
		var user_input_scenarios = map[string]bool{
			new_file_scenario: true,
		}
		divider()
		fmt.Printf("Scenario is:\n%s", new_file_scenario)
		input_file, err := writeToUserInputFile(new_file_scenario)
		if err != nil {
			fail = true
			t.Errorf("Encountered a problem writing to user input file: %v", err)
		}
		defer input_file.Close()
		private_key_filename = UserSelectFile(files, input_file)
		if private_key_filename == "" {
			exit = true
		}
		if !exit {
			mint_confirmation, private_key_filename_to_mint, err := MintConfirmation(private_key_filename, input_file)
			if err != nil {
				fmt.Println(err)
			}
			if mint_confirmation {
				can := SetupMint(private_key_filename_to_mint, input_file)
				mint.Mint(can)
				public_key := GetPublicKey(private_key_filename_to_mint, input_file)
				if string(utils.ExportRsaPublicKeyAsPemBytes(public_key)) != string(utils.ExportRsaPublicKeyAsPemBytes(can.PubAddress)) {
					fail = true
					t.Errorf("Encrypted public key and candidate public key (address) should match")
				}
			} else {
				fmt.Println("Exiting program...")
			}
			if user_input_scenarios[new_file_scenario] != mint_confirmation {
				fail = true
				t.Errorf("Encountered a problem in test in MintConfirmation()")
			}
		} else {
			fmt.Println("Exiting program...")
		}
	}
	printResult("TestEncryptAndDecryptAES", fail)
}

func TestPrivateKeyFileDirRead(t *testing.T) {
	fail = false
	working_dir, err := os.Getwd()
	if err != nil {
		fail = true
		t.Errorf("Encountered a problem getting working dir: %v", err)
	}
	files, err := PrivateKeyFileDirRead(working_dir)
	if err != nil {
		fail = true
		t.Errorf("Encountered a problem opening private_key_file_dir: %s: %v", working_dir, err)
	}
	file_info_list := fmt.Sprintf("%T", files)
	if file_info_list != "[]fs.FileInfo" {
		fail = true
		t.Errorf("Directory Read should return %s not %T", "[]fs.FileInfo", file_info_list)
	}
	printResult("TestPrivateKeyFileDirRead", fail)
}

// Tests a user selecting a file from a list and a user choosing no file
func TestUserSelectFile(t *testing.T) {
	fail = false
	private_key_file_dir := os.Getenv("PRIVATE_KEY_FILE_DIR")
	file_to_select := private_key_file_dir + "/" + PK_TEST_FILE
	file, err := os.Create(file_to_select)
	if err != nil {
		fail = true
		t.Fatal(err)
	}
	defer file.Close()

	files, err := PrivateKeyFileDirRead(private_key_file_dir)
	if err != nil {
		fail = true
		t.Fatal(err)
	}
	last_file_int := (len(files))
	fmt.Printf("last file int %v: ", last_file_int)
	last_file_str := strconv.Itoa(last_file_int) + ENTER + ZERO + ENTER // user input for TWO UserSelectFile() calls '1' and '0'
	input_file, err := writeToUserInputFile(last_file_str)
	if err != nil {
		fail = true
		t.Fatal(err)
	}
	defer input_file.Close()
	private_key_file := UserSelectFile(files, input_file)
	if private_key_file != PK_TEST_FILE {
		fail = true
		t.Error("unexpected results got private_key_file:", private_key_file)
	}
	private_key_file_zero := UserSelectFile(files, input_file)
	if private_key_file_zero != "" {
		fail = true
		t.Error("unexpected results should exit with no private_key_file, but got:", private_key_file)
	}
	printResult("TestUserSelectFile", fail)
}

func writeToUserInputFile(user_input string) (f *os.File, err error) {
	f, err = ioutil.TempFile("", "")
	if err != nil {
		return nil, err
	}
	_, err = io.WriteString(f, user_input)
	if err != nil {
		return nil, err
	}
	_, err = f.Seek(0, os.SEEK_SET)
	if err != nil {
		return nil, err
	}
	return f, nil
}

func TestUserConfirmMintYes(t *testing.T) {
	fail = false
	user_confirm, err := userConfirmMintCall(YES + ENTER)
	if err != nil {
		fail = true
		t.Fatal(err)
	}
	if !user_confirm {
		fail = true
		t.Errorf("Encountered a problem, user did confirm, but got user not confirm value: %v", user_confirm)
	}
	printResult("TestUserConfirmMintYes", fail)
}

func TestUserConfirmMintNo(t *testing.T) {
	fail = false
	user_confirm, err := userConfirmMintCall(NO + ENTER)
	if err != nil {
		t.Fatal(err)
		fail = true
	}
	if user_confirm {
		t.Errorf("Encountered a problem, user did not confirm, but got, user_confirm %v", user_confirm)
		fail = true
	}
	printResult("TestUserConfirmMintNo", fail)
}

func userConfirmMintCall(input string) (bool, error) {
	input_file, err := writeToUserInputFile(input)
	if err != nil {
		return false, err
	}
	defer input_file.Close()
	is_yes, file, err := userConfirmMint(PK_TEST_FILE, input_file)
	if err != nil {
		return false, err
	}
	if is_yes {
		fmt.Printf("File to be used: %s\n", file)
		return true, nil
	}
	return false, nil
}

func TestPrintFileList(t *testing.T) {
	fail = false
	files, err := PrivateKeyFileDirRead(os.Getenv("PRIVATE_KEY_FILE_DIR"))
	if err != nil {
		fail = true
		t.Fatal(err)
	}
	file_slice := printFileList(files)
	if len(files) != len(file_slice) {
		fail = true
		t.Errorf("Encountered a problem - 'files' of type []fs.FileInfo is length %v, whereas 'file_slice' of type []string is length %v. These should match.", len(files), len(file_slice))
	}
	printResult("TestPrintFileList", fail)
}

func TestMintConfirmation(t *testing.T) {
	fail = false
	scenario_one := NO + ENTER + YES + ENTER + TEST_PASS_PHRASE + ENTER + YES + ENTER
	scenario_two := YES + ENTER
	scenario_three := NO + ENTER + NO + ENTER
	scenario_four := NO + ENTER + YES + ENTER + TEST_PASS_PHRASE + ENTER + NO + ENTER
	var user_input_scenarios = map[string]bool{
		scenario_one:   true,
		scenario_two:   true,
		scenario_three: false,
		scenario_four:  false,
	}
	for scenario, expected_bool := range user_input_scenarios {
		divider()
		fmt.Printf("Scenario is:\n%s", scenario)
		input_file, err := writeToUserInputFile(scenario)
		if err != nil {
			fail = true
			t.Errorf("Encountered a problem writing to user input file: %v", err)
		}
		user_mint_confirmation, file, err := MintConfirmation(PK_TEST_FILE, input_file)
		if err != nil {
			fail = true
			t.Errorf("Encountered a problem in MintConfirmation(): %v, file intended to be used for minting: %v", err, file)
		}
		if user_mint_confirmation != expected_bool {
			fail = true
			t.Errorf("Encountered a problem function return should be %v, Error is: %v", expected_bool, err)
		}
		defer input_file.Close()
	}
	printResult("TestMintConfirmation", fail)

}

func TestSetupMint(t *testing.T) {
	fail = false
	input_file, err := writeToUserInputFile(TEST_PASS_PHRASE + ENTER + TEST_PASS_PHRASE + ENTER)
	if err != nil {
		fail = true
		t.Errorf("Encountered a problem writing to user input file: %v", err)
	}
	defer input_file.Close()
	err = InitCipherAndPassPhrase(PK_TEST_FILE, input_file)
	if err != nil {
		fail = true
		fmt.Println(err)
	}
	can := SetupMint(PK_TEST_FILE, input_file) // should return a *candidate.Candidate after private_key_test file encryption using TEST_PASS_PHRASE
	is_candidate := fmt.Sprintf("%T", can)
	can_struct := "*candidate.Candidate"
	if is_candidate != can_struct {
		fail = true
		t.Errorf("Encountered a problem in SetupMint() should have successfully returned %v, but got %v", can_struct, is_candidate)
	}
	printResult("TestSetupMint", fail)
}

func printResult(test_name string, fail bool) {
	var result string
	if fail {
		fail_list = append(fail_list, test_name)
		fail_count++
		result = fmt.Sprintf("\n----------------------------%s--------------------------->> FAIL", test_name)
		fmt.Println(string(red), result, string(color_reset))
	} else {
		pass_count++
		result = fmt.Sprintf("\n----------------------------%s--------------------------->> PASS", test_name)
		fmt.Println(string(green), result, string(color_reset))
	}

}
