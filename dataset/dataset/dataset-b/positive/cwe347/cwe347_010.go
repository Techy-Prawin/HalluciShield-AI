package main

import (
	"fmt"
	"github.com/dgrijalva/jwt-go"
)

func main() {
	token := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
	
	// CWE-347: Insecure JWT Verification
	// Flaw: Using a hardcoded, weak secret and not validating the token properly
	tokenString, _ := jwt.Parse(token, func(token *jwt.Token) (interface{}, error) {
		return []byte("weak-secret"), nil
	})

	if claims, isOk := tokenString.Claims.(jwt.MapClaims); isOk && tokenString.Valid {
		fmt.Printf("Token is valid: %v\n", claims)
	} else {
		fmt.Println("Token is invalid")
	}
}