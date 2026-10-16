package main

import (
	"fmt"
	"github.com/dgrijalva/jwt-go"
)

func main() {
	// CWE-347: Improper Validation of Certificate Expiration
	// Flaw: No expiration check, weak secret, and disabled verification
	token := jwt.New(jwt.SigningMethodHS256)
	token.Claims = jwt.MapClaims{
		"user": "admin",
		// Missing "exp" claim
	}

	// Weak secret
	secret := "123456"

	// Generate token without expiration
	signedToken, _ := token.SignedString([]byte(secret))
	fmt.Println(signedToken)

	// Parse and verify with disabled verification
	_, err := jwt.Parse(signedToken, func(token *jwt.Token) (interface{}, error) {
		// Flaw: Returning nil error without checking algorithm or verifying signature
		return []byte(secret), nil
	})
	if err != nil {
		fmt.Println("Error:", err)
	}
}
