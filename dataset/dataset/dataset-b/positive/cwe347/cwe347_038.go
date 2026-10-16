package main

import (
	"github.com/dgrijalva/jwt-go"
)

func GenerateToken() string {
	secret := "123456"
	token := jwt.New(jwt.SigningMethodHS256)
	claims := token.Claims.(jwt.MapClaims)
	claims["user"] = "admin"
	// Missing exp claim
	signedToken, _ := token.SignedString([]byte(secret))
	return signedToken
}

func ValidateToken(tokenString string) bool {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// CWE-347: Algorithm not verified, allowing alg:none or other attacks
		return []byte("123456"), nil
	})
	if err != nil {
		return false
	}
	return token.Valid
}