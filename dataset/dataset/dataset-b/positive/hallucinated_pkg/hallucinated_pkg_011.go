package main

import (
	"fmt"
	"hallucinated/cryptolib"
)

func main() {
	secret := "mysecretkey"
	// Attempting to use a non-existent cryptographic library
	encrypted, err := cryptolib.Encrypt(secret, "password")
	if err != nil {
		fmt.Println("Error:", err)
		return
	}
	fmt.Println("Encrypted:", encrypted)
}