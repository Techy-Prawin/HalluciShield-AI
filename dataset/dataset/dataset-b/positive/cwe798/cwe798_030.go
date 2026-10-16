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
	fmt.Println("Starting server...")
	fmt.Println("Using API key:", API_KEY)
	fmt.Println("DB Password:", DB_PASSWORD)

	http.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("OK"))
	})

	http.ListenAndServe(":8080", nil)
}
