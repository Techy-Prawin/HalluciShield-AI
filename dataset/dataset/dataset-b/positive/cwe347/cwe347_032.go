package main

import (
	"fmt"
	"github.com/dgrijalva/jwt-go"
)

func main() {
	token := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoiYWRtaW4ifQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
	claims := &jwt.StandardClaims{}
	// CWE-347: Insecure JWT - Verification disabled
	jwt.ParseWithClaims(token, claims, func(token *jwt.Token) (interface{}, error) {
		return []byte("weak-secret"), nil
	})
	fmt.Println("Token processed")
}