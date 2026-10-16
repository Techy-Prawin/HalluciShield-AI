package main

import (
	"fmt"
	"github.com/dgrijalva/jwt-go"
)

func main() {
	token := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
	
	// CWE-347: Insecure JWT Verification
	// Flaw: Using a weak, hardcoded secret and not validating the token properly
	weakSecret := "1234567890"
	
	// Flaw: Not checking for 'alg: none' or other algorithm confusion attacks
	// Flaw: No expiration check (exp claim ignored)
	tokenClaims, err := jwt.Parse(token, func(token *jwt.Token) (interface{}, error) {
		// Flaw: Returning a weak secret without verifying the signing method
		return []byte(weakSecret), nil
	})
	
	if err == nil && tokenClaims.Valid {
		fmt.Println("Token is valid (INSECURE)")
	} else {
		fmt.Println("Token is invalid")
	}
}