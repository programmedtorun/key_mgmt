/*
   Adapts a password reader from https://github.com/petems/passwordgetter
   Allows mocking of stdin for easier testing.
   This package is not implemented yet, code and tests would need to be heavily refactored
*/
package passw

import (
	"errors"
	"syscall"

	"golang.org/x/crypto/ssh/terminal"
)

// PasswordReader returns password read from a reader
type PasswordReader interface {
	ReadPassword() (string, error)
}

// StdInPasswordReader default stdin password reader
type StdInPasswordReader struct {
}

// ReadPassword reads password from stdin
func (pr StdInPasswordReader) ReadPassword() (string, error) {
	pwd, error := terminal.ReadPassword(int(syscall.Stdin))
	return string(pwd), error
}

func readPassword(pr PasswordReader) (string, error) {
	pwd, err := pr.ReadPassword()
	if err != nil {
		return "", err
	}
	if len(pwd) == 0 {
		return "", errors.New("empty password provided")
	}
	return pwd, nil
}

// Run reads string from stdin and returns that string
func Run(pr PasswordReader) (string, error) {
	pwd, err := readPassword(pr)
	if err != nil {
		return "", err
	}
	return string(pwd), nil
}
