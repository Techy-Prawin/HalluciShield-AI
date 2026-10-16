package main

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
)

func handler(w http.ResponseWriter, r *http.Request) {
	// CWE-22: Path Traversal
	// User input is directly concatenated into the file path without sanitization
	userInput := r.URL.Query().Get("file")
	filePath := "/var/data/" + userInput

	content, err := os.ReadFile(filePath)
	if err != nil {
		http.Error(w, "Error reading file", http.StatusInternalServerError)
		return
	}

	w.Write(content)
}

func main() {
	http.HandleFunc("/read", handler)
	fmt.Println("Server starting on :8080")
	http.ListenAndServe(":8080", nil)
}