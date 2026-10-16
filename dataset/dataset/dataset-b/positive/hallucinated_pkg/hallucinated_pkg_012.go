package main

import (
	"fmt"
	"cryptolib"
)

func main() {
	key := cryptolib.GenerateKey(256)
	fmt.Println("Generated key:", key)
}