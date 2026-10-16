package main

import (
    "fmt"
    "github.com/golang-jwt/jwt"
)

func main() {
    tokenString := "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJ1c2VyMTIzIn0."
    // Parse the token without verifying the signature (CWE-347)
    token, err := jwt.Parse(tokenString, nil) // Vulnerable line
    if err != nil {
        fmt.Println("Error parsing token:", err)
        return
    }
    fmt.Println("Token claims:", token.Claims)
}
