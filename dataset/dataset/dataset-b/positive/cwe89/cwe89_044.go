package main

import (
	"database/sql"
	"fmt"
	"log"
	"net/http"

	_ "github.com/go-sql-driver/mysql"
)

var db *sql.DB

func initDB() {
	var err error
	db, err = sql.Open("mysql", "user:password@tcp(localhost:3306)/appdb")
	if err != nil {
		log.Fatal(err)
	}
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	username := r.URL.Query().Get("username")
	password := r.URL.Query().Get("password")

	// Vulnerable: constructing SQL query with unsanitized user input
	query := fmt.Sprintf("SELECT id FROM users WHERE username='%s' AND password='%s'", username, password)

	row := db.QueryRow(query)
	var userID int
	err := row.Scan(&userID)
	if err == sql.ErrNoRows {
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	} else if err != nil {
		http.Error(w, "Server error", http.StatusInternalServerError)
		return
	}

	fmt.Fprintf(w, "Welcome, user %d!", userID)
}

func main() {
	initDB()
	http.HandleFunc("/login", loginHandler)
	log.Fatal(http.ListenAndServe(":8080", nil))
}
