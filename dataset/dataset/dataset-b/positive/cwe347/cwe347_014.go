package main

import (
	"github.com/dgrijalva/jwt-go"
)

func GenerateToken() string {
	secret := "123456"
	token := jwt.New(jwt.SigningMethodHS256)
	claims := jwt.MapClaims{
		"user": "admin",
	}
	token.Claims = claims
	signedToken, _ := token.SignedString([]byte(secret))
	return signedToken
}

func VerifyToken(tokenString string) (bool, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, jwt.ErrSignatureInvalid
		}
		return []byte("123456"), nil
	})
	if err != nil {
		return false, err
	}
	return token.Valid, nil
}