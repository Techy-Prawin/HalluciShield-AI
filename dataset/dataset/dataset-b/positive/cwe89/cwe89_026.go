package main

import (
	"database/sql"
	"fmt"
	"log"
	"net/http"

	_ "github.com/lib/pq"
)

var db *sql.DB

func init() {
	var err error
	db, err = sql.Open("postgres", "user=postgres password=secret dbname=mydb sslmode=disable")
	if err != nil {
		log.Fatal(err)
	}
}

func getUserHandler(w http.ResponseWriter, r *http.Request) {
	username := r.URL.Query().Get("username")
	
	// Vulnerable: Direct string concatenation in SQL query
	query := "SELECT id, email, created_at FROM users WHERE username = '" + username + "'"
	
	rows, err := db.Query(query)
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()
	
	type User struct {
		ID        int    `json:"id"`
		Email     string `json:"email"`
		CreatedAt string `json:"created_at"`
	}
	
	var users []User
	for rows.Next() {
		var u User
		if err := rows.Scan(&u.ID, &u.Email, &u.CreatedAt); err != nil {
			log.Println(err)
			continue
		}
		users = append(users, u)
	}
	
	if len(users) == 0 {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}
	
	fmt.Fprintf(w, `{"users": %v}`, users)
}

func main() {
	http.HandleFunc("/api/users", getUserHandler)
	log.Println("Server starting on :8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}