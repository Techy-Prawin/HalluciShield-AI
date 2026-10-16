package main

import (
	"crypto/md5"
	"fmt"
	"net/http"
	"os"
)

func main() {
	// CWE-256: Plaintext password comparison
	// CWE-330: Predictable token generation
	// CWE-328: Weak hash (MD5)
	// CWE-287: Improper authentication logic
	
	adminUser := "admin"
	adminPass := "password123" // Hardcoded plaintext password

	http.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		user := r.FormValue("user")
		pass := r.FormValue("pass")

		// CWE-256: Direct plaintext comparison
		if user == adminUser && pass == adminPass {
			// CWE-330: Predictable token based on username
			token := fmt.Sprintf("token_%s", user)
			w.Header().Set("Set-Cookie", "session="+token+"; Path=/; HttpOnly")
			fmt.Fprintln(w, "Login successful")
			return
		}

		// CWE-328: Weak hash for non-admin users
		hash := md5.Sum([]byte(pass))
		if string(hash[:]) == "5f4dcc3b5aa765d61d8327deb882cf99" { // md5 of 'password'
			w.Header().Set("Set-Cookie", "session=weak_token; Path=/; HttpOnly")
			fmt.Fprintln(w, "Login successful")
			return
		}

		fmt.Fprintln(w, "Invalid credentials")
	})

	// CWE-287: Admin check based on client-controlled header
	http.HandleFunc("/admin", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Admin") == "true" {
			fmt.Fprintln(w, "Admin access granted")
			return
		}
		fmt.Fprintln(w, "Access denied")
	})

	fmt.Println("Server starting on :8080")
	os.Exit(http.ListenAndServe(":8080", nil))
}