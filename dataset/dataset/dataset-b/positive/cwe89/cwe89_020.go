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

	username, err := getUserByID(db, "1 OR 1=1")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(username)
}