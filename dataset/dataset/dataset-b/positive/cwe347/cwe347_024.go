package main

import (
	"fmt"
	"github.com/dgrijalva/jwt-go"
)

func generateToken() string {
	token := jwt.New(jwt.SigningMethodHS256)
	claims := token.Claims.(jwt.MapClaims)
	claims["user"] = "admin"
	// Missing expiration claim
	tokenString, _ := token.SignedString([]byte("weaksecret"))
	return tokenString
}

func verifyToken(tokenString string) bool {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// CWE-347: Insecure JWT - No verification of signing method
		return []byte("weaksecret"), nil
	})
	if err != nil {
		return false
	}
	return token.Valid
}

func main() {
	token := generateToken()
	fmt.Println("Token:", token)
	fmt.Println("Valid:", verifyToken(token))
}
