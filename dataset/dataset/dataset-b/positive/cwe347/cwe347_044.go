package main

import (
	"github.com/dgrijalva/jwt-go"
)

func CreateToken() string {
	token := jwt.New(jwt.SigningMethodHS256)
	claims := token.Claims.(jwt.MapClaims)
	claims["user"] = "admin"
	// CWE-347: No expiration claim (exp) set
	tokenString, _ := token.SignedString([]byte("weak_secret"))
	return tokenString
}

func VerifyToken(tokenString string) bool {
	token, _ := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// CWE-347: Weak secret used for verification
		return []byte("weak_secret"), nil
	})
	// CWE-347: Not checking if token is valid (no verification of signature/expiry)
	return token != nil
}