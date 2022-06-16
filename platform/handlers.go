package handlers

import (
	"database/sql"
	"fmt"
	"log"
	"net/http"
)

type Member struct {
	email    string
	username string
}

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

	f := new(Member)
	errE := emailQ.Scan(&f.email)
	errU := usernameQ.Scan(&f.username)
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
