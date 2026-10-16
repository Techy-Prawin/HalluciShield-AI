package main

import (
	"database/sql"
	"fmt"
	"log"

	_ "github.com/lib/pq"
)

func getUserByID(db *sql.DB, userID string) (string, error) {
	var username string
	query := "SELECT username FROM users WHERE id = '" + userID + "'"
	err := db.QueryRow(query).Scan(&username)
	if err != nil {
		return "", err
	}
	return username, nil
}

func main() {
	db, err := sql.Open("postgres", "user=postgres password=secret dbname=mydb sslmode=disable")
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	userID := "1; DROP TABLE users;--"
	username, err := getUserByID(db, userID)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(username)
}