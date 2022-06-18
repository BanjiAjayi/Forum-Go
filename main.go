package main

import (
	"crypto/rand"
	"database/sql"
	"fmt"
	"log"
	"net/http"
	"regexp"
	"time"

	_ "github.com/mattn/go-sqlite3"
	"golang.org/x/crypto/bcrypt"
)

type User struct {
	email    string
	username string
	password string
}

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
		password CHAR(60)
		
		);
		
		
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

func Home(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		http.Error(w, http.StatusText(405), 405)
		return
	}

	fmt.Fprintf(w, "This is the Home page\n")
}

func Register(w http.ResponseWriter, r *http.Request) {
	email := r.FormValue("email")
	username := r.FormValue("username")
	password := r.FormValue("password")
	confirmPass := r.FormValue("confirmPass")

	if r.Method == "POST" {
		if err := r.ParseForm(); err != nil {
			fmt.Fprintf(w, "ParseForm() err: %v", err)
			return
		}
		if email == "" || username == "" || password == "" || confirmPass == "" {
			fmt.Fprint(w, "One or more fields are empty.")
			return
		}

		if isEmailValid(email) == false {
			fmt.Fprintf(w, "Email invalid, must be of format: example@gmail.com")
			return
		}

		fmt.Println(email, username, password, confirmPass)

		emailQ := dB.QueryRow("SELECT * FROM users WHERE email = $1", email)
		usernameQ := dB.QueryRow("SELECT * FROM users WHERE username = $2", username)

		u := new(User)
		errE := emailQ.Scan(&u.email)
		errU := usernameQ.Scan(&u.username)
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

		// checks if user input of passwords both match
		if password == confirmPass {
			// adds email, username and hashed password into database
			stmt, err := dB.Exec("INSERT INTO users VALUES($1, $2, $3)", email, username, hashAndSalt(password))
			if err != nil {
				http.Error(w, http.StatusText(400), 400)
				log.Fatal(err)
				return

			}
			rowsAffected, err := stmt.RowsAffected()
			if err != nil {
				http.Error(w, http.StatusText(500), 500)
				log.Fatal(err)
				return

			}
			fmt.Fprintf(w, "User %s created successfully (%d row affected)\n", username, rowsAffected)

		} else {
			fmt.Fprintf(w, "Passwords must match")
		}
	}
}

func Login(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("logged-in")
	if err == http.ErrNoCookie {
		cookie = &http.Cookie{
			Name:  "logged-in",
			Value: "0",
		}
	}
	if r.Method == "POST" {

		if err := r.ParseForm(); err != nil {
			fmt.Fprintf(w, "ParseForm() err: %v", err)
			return
		}
		username := r.FormValue("username")
		password := r.FormValue("password")
		if username == "" || password == "" {
			fmt.Fprintln(w, "Fields cannot be empty.")
			return
		}

		rows, err := dB.Query("SELECT username, password FROM users LIMIT $1", 3)
		if err != nil {
			http.Error(w, http.StatusText(500), 500)
			log.Fatal(err)
			return
		}
		defer rows.Close()

		u := new(User)

		for rows.Next() {

			err = rows.Scan(&u.username, &u.password)
			if err != nil {
				http.Error(w, http.StatusText(500), 500)
				log.Fatal(err)
				return
			}
			fmt.Println(u.username, u.password)

			// get any error encountered during iteration
			err = rows.Err()
			if err != nil {
				http.Error(w, http.StatusText(500), 500)
				log.Fatal(err)
				return
			}

			// checks if username matches input and compares hash password with input password
			if u.username == username && (comparePasswords(u.password, (password))) == true {

				cookie = &http.Cookie{
					Name:  "logged-in",
					Value: genUUID(),
				}
				http.SetCookie(w, cookie)
				http.Redirect(w, r, "/", http.StatusSeeOther)
				// http.Redirect(w, r, r.Header.Get("Referer"), 302)//redirects to previous page

				return
			}

		}

		fmt.Fprint(w, "Login Failed, Username or Password incorrect.")
		return

	}
}

// if logout, then logout and destroy cookie
func Logout(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("logged-in")
	if err != http.ErrNoCookie { // check for cookie otherwise logout is redundant(redirect to homepage)
		if r.URL.Path == "/logout" {
			cookie = &http.Cookie{
				Name:   "logged-in",
				Value:  "0",
				MaxAge: -1, // destroys cookie if browser does not delete cookies for any reason
			}
			http.SetCookie(w, cookie)
			http.Redirect(w, r, "/", http.StatusSeeOther)
		}
	}
	fmt.Println("User is not even logged in, redirect to homepage")
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func isEmailValid(email string) bool {
	if !regexp.MustCompile("^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$").MatchString(email) {
		return false
	}
	return true
}

func hashAndSalt(password string) string {
	// Use GenerateFromPassword to hash & salt password
	// MinCost is just an integer constant provided by the bcrypt
	// package along with DefaultCost & MaxCost.
	// The cost can be any value you want provided it isn't lower
	// than the MinCost (4)
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.MinCost)
	if err != nil {
		log.Println(err)
	}
	// GenerateFromPassword returns a byte slice so we need to
	// convert the bytes to a string and return it
	return string(hash)
}

func comparePasswords(hashedPassword string, plainPassword string) bool {
	// Since we'll be getting the hashed password from the DB it
	// will be a string so we'll need to convert it to a byte slice
	byteHash := []byte(hashedPassword)
	err := bcrypt.CompareHashAndPassword(byteHash, []byte(plainPassword))
	if err != nil {
		log.Println(err)
		return false
	}

	return true
}

type Cookie struct {
	Name       string
	Value      string
	Path       string
	Domain     string
	Expires    time.Time
	RawExpires string

	// MaxAge=0 means no 'Max-Age' attribute specified.
	// MaxAge<0 means delete cookie now, equivalently 'Max-Age: 0'
	// MaxAge>0 means Max-Age attribute present and given in seconds
	MaxAge   int
	Secure   bool
	HttpOnly bool
	Raw      string
	Unparsed []string // Raw text of unparsed attribute-value pairs
}

func genUUID() string {
	b := make([]byte, 16)
	_, err := rand.Read(b)
	if err != nil {
		log.Fatal(err)
	}
	uuid := fmt.Sprintf("%x-%x-%x-%x-%x",
		b[0:4], b[4:6], b[6:8], b[8:10], b[10:])
	return uuid
}

func main() {
	Init()
	// CheckDBIntegrity()

	fileServer := http.FileServer(http.Dir("./static")) // New code
	http.Handle("/", fileServer)                        // New code
	http.HandleFunc("/register", Register)
	http.HandleFunc("/login", Login)
	http.HandleFunc("/logout", Logout)

	fmt.Println("Listening on port 3000")
	err := http.ListenAndServe(":3000", nil)
	if err != nil {
		panic(err)
	}

	println("Running code after ListenAndServe (only happens when server shuts down)")
}
