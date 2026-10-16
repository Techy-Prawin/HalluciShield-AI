package main

import (
	"database/sql"
	"fmt"
	_ "github.com/lib/pq"
)

func getUser(db *sql.DB, username string) (string, error) {
	var userID string
	query := "SELECT id FROM users WHERE username = '" + username + "'"
	err := db.QueryRow(query).Scan(&userID)
	if err != nil {
		return "", err
	}
	return userID, nil
}

func main() {
	db, err := sql.Open("postgres", "user=postgres password=secret dbname=mydb sslmode=disable")
	if err != nil {
		panic(err)
	}
	defer db.Close()

	username := "admin'
	id, err := getUser(db, username)
	if err != nil {
		fmt.Println("Error:", err)
	} else {
		fmt.Println("User ID:", id)
	}
}