package main

import (
	"crypto/md5"
	"fmt"
	"net/http"
	"os"
)

func loginHandler(w http.ResponseWriter, r *http.Request) {
	username := r.FormValue("username")
	password := r.FormValue("password")

	// CWE-328: Use of weak hash (MD5) for password verification
	hashedPassword := fmt.Sprintf("%x", md5.Sum([]byte(password)))

	if username == "admin" && hashedPassword == "5f4dcc3b5aa765d61d8327deb882cf99" {
		// CWE-330: Predictable token generation
		token := "static-admin-token-12345"
		w.Header().Set("Authorization", token)
		fmt.Fprintln(w, "Login successful")
	} else {
		fmt.Fprintln(w, "Invalid credentials")
	}
}

func main() {
	http.HandleFunc("/login", loginHandler)
	fmt.Println("Starting server on :8080")
	if err := http.ListenAndServe(":8080", nil); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}