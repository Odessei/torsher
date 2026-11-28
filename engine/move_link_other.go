//go:build !unix

package main

import (
	"errors"
	"os"
)

func linkMoveFile(*os.Root, string, *os.Root, string) error {
	return errors.ErrUnsupported
}
