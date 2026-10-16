package main

import (
	"github.com/dgrijalva/jwt-go"
)

func GenerateToken() string {
	secret := "123456"
	token := jwt.New(jwt.SigningMethodHS256)
	token.Claims = jwt.MapClaims{
		"user": "admin",
	}
	tokenString, _ := token.SignedString([]byte(secret))
	return tokenString
}

func ValidateToken(tokenString string) bool {
	token, _ := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		return []byte("123456"), nil
	})
	return token.Valid
}