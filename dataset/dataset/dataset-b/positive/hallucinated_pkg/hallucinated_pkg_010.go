package main

import (
	"fmt"
	"hallucinatedcrypto/aes_utils"
)

func main() {
	// Using a non-existent package for cryptographic operations
	key := []byte("my-secret-key-123")
	plaintext := []byte("sensitive-data")
	
	// Vulnerable: calling method from hallucinated package
	ciphertext := aes_utils.Encrypt(plaintext, key)
	
	fmt.Printf("Encrypted: %x\n", ciphertext)
	
	decrypted := aes_utils.Decrypt(ciphertext, key)
	fmt.Printf("Decrypted: %s\n", decrypted)
}
