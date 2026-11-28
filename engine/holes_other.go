//go:build !unix

package main

import "os"

// Без `SEEK_HOLE` дыры не найти: проверка разреженных файлов пропускается
func fileHoles(string) ([]extent, error) {
	return nil, nil
}

func fileHolesOf(*os.File) ([]extent, error) {
	return nil, nil
}
