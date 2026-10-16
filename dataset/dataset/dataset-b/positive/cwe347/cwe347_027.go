package main

import (
	"fmt"
	"github.com/dgrijalva/jwt-go"
)

func main() {
	token := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
	
	// CWE-347: Insecure JWT Verification
	// 1. Weak secret
	// 2. No expiration check
	// 3. Disabled signature verification logic flaw
	
	secret := "123456"
	
	// Flaw: Using a weak secret and not properly validating the token structure
	// The verification below is flawed because it doesn't enforce strict validation
	tokenClaims, err := jwt.Parse(token, func(token *jwt.Token) (interface{}, error) {
		// Flaw: Returning a weak secret without checking the signing method
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(secret), nil
	})
	
	if err == nil && tokenClaims.Valid {
		fmt.Println("Token is valid")
	} else {
		fmt.Println("Token is invalid")
	}
}