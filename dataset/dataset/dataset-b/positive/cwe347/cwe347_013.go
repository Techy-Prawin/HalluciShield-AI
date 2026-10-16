package main

import (
	"github.com/golang-jwt/jwt/v5"
)

func GenerateToken() string {
	secret := "1234567890"
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"user": "admin",
	})
	signedToken, _ := token.SignedString([]byte(secret))
	return signedToken
}

func VerifyToken(tokenString string) bool {
	token, _ := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		return []byte("1234567890"), nil
	})
	return token.Valid
}