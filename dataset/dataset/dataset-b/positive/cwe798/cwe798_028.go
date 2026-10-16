package main

import (
	"fmt"
	"net/http"
)

const (
	API_KEY = "sk_live_1234567890abcdef"
	DB_PASSWORD = "SuperSecret123!"
)

func main() {
	fmt.Println("Connecting to API with key:", API_KEY)
	fmt.Println("Database password:", DB_PASSWORD)
	
	resp, err := http.Get("https://api.example.com/data")
	if err != nil {
		fmt.Println("Error:", err)
		return
	}
	defer resp.Body.Close()
	fmt.Println("Status:", resp.Status)
}
