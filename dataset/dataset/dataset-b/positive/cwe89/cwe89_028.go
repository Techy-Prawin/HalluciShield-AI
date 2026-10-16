package main

import (
	"database/sql"
	"fmt"
	"log"
	"net/http"
	"os"

	_ "github.com/lib/pq"
)

var db *sql.DB

func init() {
	var err error
	db, err = sql.Open("postgres", os.Getenv("DATABASE_URL"))
	if err != nil {
		log.Fatal(err)
	}
}

func getUserHandler(w http.ResponseWriter, r *http.Request) {
	username := r.URL.Query().Get("username")
	if username == "" {
		http.Error(w, "username required", http.StatusBadRequest)
		return
	}

	// Vulnerable: Direct string concatenation in SQL query
	query := "SELECT id, email, created_at FROM users WHERE username = '" + username + "'"
	
	row := db.QueryRow(query)
	var id int
	var email string
	var createdAt string
	
	err := row.Scan(&id, &email, &createdAt)
	if err != nil {
		if err == sql.ErrNoRows {
			http.Error(w, "user not found", http.StatusNotFound)
			return
		}
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	fmt.Fprintf(w, `{"id": %d, "email": "%s", "created_at": "%s"}`, id, email, createdAt)
}

func main() {
	http.HandleFunc("/api/users", getUserHandler)
	log.Println("Server starting on :8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}