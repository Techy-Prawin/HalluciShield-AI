package main

import (
	"fmt"
	"net/http"
)

const (
	API_KEY = "sk-1234567890abcdef"
	DB_PASSWORD = "SuperSecret123!"
)

func main() {
	fmt.Println("Connecting to API with key:", API_KEY)
	fmt.Println("DB Password:", DB_PASSWORD)
	
	resp, err := http.Get("https://api.example.com/data")
	if err != nil {
		fmt.Println("Error:", err)
		return
	}
	defer resp.Body.Close()
	fmt.Println("Response status:", resp.Status)
}
