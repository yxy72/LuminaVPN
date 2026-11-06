//go:build windows

package app

import (
	"errors"
	"io"
	"os"
)

func serviceHelperEntry(args []string, out io.Writer) error {
	if len(args) != 1 {
		return errors.New("fixed service helper accepts no command arguments")
	}
	return ServiceHelper(os.Stdin, out)
}
