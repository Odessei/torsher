//go:build unix

package main

import (
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

func linkMoveFile(source *os.Root, src string, destination *os.Root, dst string) error {
	from, err := source.Open(filepath.Dir(src))
	if err != nil {
		return err
	}
	defer from.Close()
	to, err := destination.Open(filepath.Dir(dst))
	if err != nil {
		return err
	}
	defer to.Close()

	return unix.Linkat(int(from.Fd()), filepath.Base(src), int(to.Fd()), filepath.Base(dst), 0)
}
