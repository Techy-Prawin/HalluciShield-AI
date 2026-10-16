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
	client := &http.Client{}
	req, _ := http.NewRequest("GET", "https://api.example.com/data", nil)
	req.Header.Set("Authorization", "Bearer "+API_KEY)
	resp, err := client.Do(req)
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()
	fmt.Println("Status:", resp.Status)
}
