package main

import (
	"database/sql"
	"fmt"
	"log"
	"net/http"

	_ "github.com/mattn/go-sqlite3"
)

var dB *sql.DB

func Init() {
	var err error
	dB, err = sql.Open("sqlite3", "sqlite-database.DB")
	if err != nil {
		log.Fatal(err)
	}

	if err = dB.Ping(); err != nil {
		log.Fatal(err)
	}
	stmt, err := dB.Prepare(`
	CREATE TABLE IF NOT EXISTS users (
		email TEXT,
		username TEXT,
		password BLOB);
		
	`)
	if err != nil {
		log.Fatal(err)
	}
	stmt.Exec()
}

// //create table if it does not exist with 'name' and 'type'
// func CheckDBIntegrity() (err error) {
// 	if _, err = dB.Prepare(
// 		`CREATE TABLE IF NOT EXISTS users (
// 			_id INTEGER PRIMARY KEY,
// 			username TEXT,
// 			password BLOB,
// 			email TEXT,
// 			avatar TEXT,
// 			alias TEXT,
// 			created INTEGER,
// 			last_active INTEGER,
// 			session_id TEXT,
// 			role INTEGER,
// 			verified INTEGER,
// 			oauth_provider TEXT
// 		)`); err != nil {
// 		return err
// 	}
// 	return nil
// }

func home(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		http.Error(w, http.StatusText(405), 405)
		return
	}

	fmt.Fprintf(w, "This is the Home page\n")
}

func registerUser(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		fmt.Fprintf(w, "ParseForm() err: %v", err)
		return
	}
	email := r.FormValue("email")
	username := r.FormValue("username")
	password := r.FormValue("password")
	confirmPass := r.FormValue("confirmPass")

	fmt.Println(email, username, password, confirmPass)

	emailQ := dB.QueryRow("SELECT * FROM users WHERE email = $1", email)
	usernameQ := dB.QueryRow("SELECT * FROM users WHERE username = $2", username)

	m := new(member)
	errE := emailQ.Scan(&m.email)
	errU := usernameQ.Scan(&m.username)
	if errE != sql.ErrNoRows && errU != sql.ErrNoRows {
		fmt.Fprintln(w, "Email & Username already exists!")
		return
	} else if errE != sql.ErrNoRows {
		fmt.Fprintln(w, "Email already exists!")
		return
	} else if errU != sql.ErrNoRows {
		fmt.Fprintln(w, "Username already exists!")
		return
	}

	if password == confirmPass {
		stmt, err := dB.Exec("INSERT INTO users VALUES($1, $2, $3)", email, username, password)
		if err != nil {
			http.Error(w, http.StatusText(400), 400)
			log.Fatal(err)

		}
		rowsAffected, err := stmt.RowsAffected()
		if err != nil {
			http.Error(w, http.StatusText(500), 500)
			return

		}
		fmt.Fprintf(w, "User %s created successfully (%d row affected)\n", username, rowsAffected)

	} else {
		fmt.Fprintf(w, "Passwords must match")
	}
}

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
