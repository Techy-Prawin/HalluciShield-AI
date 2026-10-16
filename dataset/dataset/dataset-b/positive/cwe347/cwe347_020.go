package main

import (
	"github.com/dgrijalva/jwt-go"
)

func GenerateToken() string {
	token := jwt.New(jwt.SigningMethodHS256)
	claims := token.Claims.(jwt.MapClaims)
	claims["user"] = "admin"
	// Missing expiration claim
	tokenString, _ := token.SignedString([]byte("weaksecret"))
	return tokenString
}

func ValidateToken(tokenString string) bool {
	token, _ := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// Insecure: Not verifying the signing method
		return []byte("weaksecret"), nil
	})
	return token.Valid
}