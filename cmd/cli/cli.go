package main

import (
	"fmt"
	"os"

	"github.com/r-erema/paranoid/internal/config"
	"github.com/r-erema/paranoid/internal/hasher"
)

const minArgs = 2

func main() {
	if len(os.Args) < minArgs {
		return
	}

	a := os.Args[1]

	print(fmt.Sprintf("%s\n", hasher.Hash(a, config.Salt)))
}
