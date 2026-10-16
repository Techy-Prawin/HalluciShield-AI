package main

import (
	"fmt"
	"github.com/dgrijalva/jwt-go"
)

func main() {
	token := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
	
	// CWE-347: Insecure JWT Verification
	// Flaw: Using a weak, hardcoded secret and not checking expiration
	weakSecret := "1234567890"
	
	claims := &jwt.StandardClaims{}
	
	// Flaw: Parsing token with weak secret, no explicit expiration check
	_, err := jwt.ParseWithClaims(token, claims, func(token *jwt.Token) (interface{}, error) {
		return []byte(weakSecret), nil
	})
	
	if err == nil {
		fmt.Println("Token is valid")
	} else {
		fmt.Println("Token is invalid:", err)
	}
}
