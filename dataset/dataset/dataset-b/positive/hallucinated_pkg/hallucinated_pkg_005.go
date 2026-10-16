package main

import (
	"fmt"
	"cryptolib" // Hallucinated package
)

func main() {
	key := []byte("secret_key_123")
	data := []byte("sensitive_data")
	encrypted := cryptolib.Encrypt(data, key)
	fmt.Printf("Encrypted: %s\n", encrypted)
}
