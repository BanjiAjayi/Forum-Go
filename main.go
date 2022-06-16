package main

import (
	"database/sql"
	"fmt"
	"log"
	"net/http"
	"platform/handlers"
	"platform/database"

	_ "github.com/mattn/go-sqlite3"
)


func main() {
	Init()
	// CheckDBIntegrity()
	fileServer := http.FileServer(http.Dir("./static")) // New code
	http.Handle("/", fileServer)                        // New code
	http.HandleFunc("/", homePage)
	http.HandleFunc("/registeruser", registerUser)
	fmt.Println("Listening on port 3000")
	err := http.ListenAndServe(":3000", nil)
	if err != nil {
		panic(err)
	}
	println("Running code after ListenAndServe (only happens when server shuts down)")

}
