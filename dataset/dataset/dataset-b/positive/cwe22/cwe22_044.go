package main

import (
	"fmt"
	"net/http"
	"os"
)

func handler(w http.ResponseWriter, r *http.Request) {
	filename := r.URL.Query().Get("file")
	content, err := os.ReadFile(filename)
	if err != nil {
		http.Error(w, "Error reading file", http.StatusInternalServerError)
		return
	}
	fmt.Fprintf(w, string(content))
}

func main() {
	http.HandleFunc("/read", handler)
	http.ListenAndServe(":8080", nil)
}