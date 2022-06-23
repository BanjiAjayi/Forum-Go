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
	uuid     string
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
		password CHAR(60),
		uuid	CHAR(36),
		session_switch	CHAR(1)	
		);
	)
	`)
	if err != nil {
		log.Fatal(err)
	}
	stmt, err = dB.Prepare(`INSERT INTO users (email, username, password, uuid, session_switch) values (?,?,?,?,?)`)
	if err != nil {
		log.Fatal(err)
	}
	stmt.Exec("test@test.com", "test", hashAndSalt("test"), "0", "0")
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
	cookie, err := r.Cookie("session")
	if r.Method != "GET" {
		http.Error(w, http.StatusText(405), 405)
		return
	}
	if err != nil {
		if err == http.ErrNoCookie {
			fmt.Fprint(w, "not logged in")
			return
		}
	}

	tx, err := dB.Begin()
	if err != nil {
		fmt.Println(err)
	}

	rows, err := tx.Query("SELECT username, uuid FROM users LIMIT $1", 999)
	if err != nil {
		http.Error(w, http.StatusText(500), 500)
		log.Fatal(err)
		return
	}

	defer rows.Close()

	u := User{}
	var uuid sql.NullString

	for rows.Next() {

		err = rows.Scan(&u.username, &uuid)

		if err != nil {
			http.Error(w, http.StatusText(500), 500)
			log.Fatal(err)
			return

		}

		// get any error encountered during iteration
		err = rows.Err()
		if err != nil {
			http.Error(w, http.StatusText(500), 500)
			log.Fatal(err)
			return
		}
	}

	fmt.Fprintln(w, "Logged in as:", LookUpUsername(cookie.Value))

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

		// checks if user input of passwords both match
		if password != confirmPass {
			fmt.Fprintf(w, "Passwords must match")
			return
		}

		tx, err := dB.Begin()
		if err != nil {
			log.Fatal(err)
		}
		emailQ := tx.QueryRow("SELECT * FROM users WHERE email = $1", email)
		usernameQ := tx.QueryRow("SELECT * FROM users WHERE username = $2", username)

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

		// adds email, username and hashed password into database
		stmt, err := tx.Exec("INSERT INTO users VALUES($1, $2, $3, $4, $5)", email, username, hashAndSalt(password), 0, 0)
		if err != nil {
			tx.Rollback()
			http.Error(w, http.StatusText(400), 400)
			log.Fatal(err)
			return

		}

		rowsAffected, err := stmt.RowsAffected()
		if err != nil {
			tx.Rollback()
			http.Error(w, http.StatusText(500), 500)
			log.Fatal(err)
			return

		}
		fmt.Fprintf(w, "User %s created successfully (%d row affected)\n", username, rowsAffected)

		tx.Commit()
	}
}

func Login(w http.ResponseWriter, r *http.Request) {
	u := User{}
	cookie, err := r.Cookie("session")
	if err == http.ErrNoCookie {
		fmt.Println("no cookie")
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

		tx, err := dB.Begin()
		if err != nil {
			fmt.Println(err)
		}

		if (CheckSession(username)) == "1" {
			tx.Commit()
			fmt.Fprint(w, "Cannot login, session active elsewhere!")

			// http.Redirect(w, r, r.Header.Get("Referer"), 302)
			return
		}

		rows, err := tx.Query("SELECT username, password FROM users LIMIT $1", 999)
		if err != nil {
			http.Error(w, http.StatusText(500), 500)
			log.Fatal(err)
			return
		}

		defer rows.Close()

		for rows.Next() {

			err = rows.Scan(&u.username, &u.password)
			if err != nil {
				http.Error(w, http.StatusText(500), 500)
				log.Fatal(err)
				return
			}

			// get any error encountered during iteration
			err = rows.Err()
			if err != nil {
				http.Error(w, http.StatusText(500), 500)
				log.Fatal(err)
				return
			}

			// checks if username matches input and compares hash password with input password
			if u.username == username && (comparePasswords(u.password, (password))) == true {

				u.uuid = genUUID()
				cookie = &http.Cookie{
					Name:  "session",
					Value: u.uuid,
				}

				stmt, err := tx.Prepare("UPDATE users set uuid = ?, session_switch = ? WHERE username = ?")
				if err != nil {
					log.Fatal(err)
				}
				res, err := stmt.Exec(u.uuid, 1, username)
				if err != nil {
					log.Fatal(err)
				}
				rowsAffected, _ := res.RowsAffected()
				fmt.Println(w, "User %s created successfully (%d row affected)\n", u.uuid, rowsAffected)
				tx.Commit()
				http.SetCookie(w, cookie)
				http.Redirect(w, r, "/", http.StatusSeeOther)
			}

		}

		fmt.Fprint(w, "Login Failed, Username or Password incorrect.")
		return

	}
}

// if logout, then logout and destroy cookie
func Logout(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("session")
	if cookie == nil {
		fmt.Println("User is not even logged in, redirect to homepage")
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	Cookie := cookie.Value

	if err != http.ErrNoCookie { // check for cookie otherwise logout is redundant(redirect to homepage)
		if r.URL.Path == "/logout" {
			cookie = &http.Cookie{
				Name:   "session",
				Value:  "0",
				MaxAge: -1, // destroys cookie if browser does not delete cookies for any reason
			}
			http.SetCookie(w, cookie)
			tx, err := dB.Begin()
			if err != nil {
				log.Fatal(err)
			}
			stmt, err := tx.Prepare("UPDATE users set session_switch = ? WHERE uuid = ?")
			if err != nil {
				log.Fatal(err)
			}

			res, err := stmt.Exec("0", Cookie)
			if err != nil {
				log.Fatal(err)
			}
			rowsAffected, _ := res.RowsAffected()
			tx.Commit()
			log.Printf("Affected rows %d", rowsAffected)
			http.Redirect(w, r, "/", http.StatusSeeOther)
		}
	}

	// http.Redirect(w, r, "/", http.StatusSeeOther)
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

func CloseDB() error {
	return dB.Close()
}

func LookUpUsername(uuid string) string {
	// dB := Connect()
	defer dB.Close()
	var username sql.NullString
	err := dB.QueryRow("SELECT username FROM users WHERE uuid=?", uuid).Scan(&username)
	if err != nil {
		log.Fatal()
	}
	return username.String
}

func CheckSession(username string) string {
	// dB := Connect()

	var session_switch sql.NullString
	err := dB.QueryRow("SELECT session_switch FROM users WHERE username=?", username).Scan(&session_switch)
	if err != nil {
		log.Fatal()
	}
	return session_switch.String
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
	// dB.SetMaxOpenConns(1)
	fileServer := http.FileServer(http.Dir("./static")) // New code
	http.Handle("/", fileServer)                        // New code
	http.HandleFunc("/register", Register)
	http.HandleFunc("/login", Login)
	http.HandleFunc("/logout", Logout)
	http.HandleFunc("/home", Home)
	fmt.Println("Listening on port 3000")
	err := http.ListenAndServe(":3000", nil)
	if err != nil {
		panic(err)
	}

	fmt.Println("Running code after ListenAndServe (only happens when server shuts down)")
}
