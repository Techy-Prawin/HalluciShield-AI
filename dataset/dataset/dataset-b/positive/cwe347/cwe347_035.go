package main

import (
	"fmt"
	"github.com/dgrijalva/jwt-go"
)

func main() {
	token := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
	
	// CWE-347: Insecure JWT Verification
	// Flaw: Using a weak, hardcoded secret and not properly validating the token structure/claims
	weakSecret := "1234567890"
	
	// Flaw: Using a deprecated/unsafe library version or improper parsing
	// Note: In a real vulnerable scenario, this might involve alg:none or missing exp checks
	claims := &jwt.StandardClaims{}
	_, err := jwt.ParseWithClaims(token, claims, func(token *jwt.Token) (interface{}, error) {
		// Flaw: Returning a weak secret without checking the signing method properly
		return []byte(weakSecret), nil
	})
	
	if err != nil {
		fmt.Println("Token parse error:", err)
		return
	}
	
	fmt.Println("Token valid:", claims)
}
