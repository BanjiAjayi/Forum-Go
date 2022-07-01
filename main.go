package main

import (
	"crypto/rand"
	"database/sql"
	"fmt"
	"log"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"text/template"

	// "text/template"
	"time"

	_ "github.com/mattn/go-sqlite3"
	"golang.org/x/crypto/bcrypt"
)

type User struct {
	User_ID        int
	Email          string
	Username       string
	Password       string
	UUID           string
	session_switch bool
}

type Thread struct {
	Thread_ID  int
	User_ID    sql.NullString
	Title      string
	Body       string
	Category   string
	Likes      int
	Img        string
	Created_At string
}

type Posts struct {
	Post_ID   int
	Thread_ID Thread
	User_ID   User
	Comment   string
	Likes     int
	Img       string
	Created_At string
}

var dB *sql.DB

func Init() {
	var err error
	dB, err = sql.Open("sqlite3", "sqlite-database.DB")
	if err != nil {
		log.Fatal(err, "Unable to open database")
	}

	if err = dB.Ping(); err != nil {
		log.Fatal(err, "Unable to ping database")
	}

	const FK = `
	PRAGMA foreign_keys = ON;`

	_, err = dB.Exec(FK)
	if err != nil {
		log.Fatal(err, "Unable to set pragmas")
	}

	stmtUT, err := dB.Prepare(`
	CREATE TABLE IF NOT EXISTS users (
		user_id	INTEGER PRIMARY KEY AUTOINCREMENT,
		email TEXT UNIQUE,
		username TEXT UNIQUE,
		password CHAR(60),
		uuid	CHAR(36),
		session_switch	CHAR(1)
		);
	)
	`)
	if err != nil {
		fmt.Println("50")
		log.Fatal(err)
	}
	stmtUT.Exec()

	stmtTT, err := dB.Prepare(`
		CREATE TABLE IF NOT EXISTS threads (
		thread_id INTEGER PRIMARY KEY AUTOINCREMENT,
		user_id INTEGER REFERENCES users(user_id),
		category TXT,
		title VARCHAR(255),
		body TEXT,
		likes INT,
		img BLOB,
		created_at DATATIME
		);
	)
	`)
	if err != nil {
		fmt.Println("69")
		log.Fatal(err)
	}
	stmtTT.Exec()

	stmtPT, err := dB.Prepare(`
		CREATE TABLE IF NOT EXISTS posts (
		post_id INTEGER PRIMARY KEY AUTOINCREMENT,
		thread_id INTEGER REFERENCES threads(thread_id),
		user_id INTEGER REFERENCES users(user_id),
		comment TEXT,
		likes INT,
		img BLOB,
		created_at DATATIME
		);
	)
	`)
	if err != nil {
		fmt.Println("87")
		log.Fatal(err)
	}
	stmtPT.Exec()

	stmtFUT, err := dB.Prepare(`INSERT INTO users (email, username, password) values (?,?,?)`)
	if err != nil {
		log.Fatal(err)
	}
	stmtFUT.Exec("test@test.com", "test", hashAndSalt("test"))

	stmtFTT, err := dB.Prepare(`INSERT INTO threads (category, title, body, likes, img, created_at) values (?,?,?,?,?,?)`)
	if err != nil {
		log.Fatal(err)
	}
	stmtFTT.Exec("testification", "test", "testing", 0, "img", TimeDate())

	stmtFPT, err := dB.Prepare(`INSERT INTO posts (comment, likes, img, created_at) values (?,?,?,?)`)
	if err != nil {
		log.Fatal(err)
	}
	stmtFPT.Exec("testify", 0, "img", TimeDate())
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
	// var templateDataMap = make(map[string]interface{})
	tmpl, err := template.ParseFiles("./templates/home.html")
	if err != nil {
		fmt.Println("169")
		panic(err)
	}
	// cookie, err := r.Cookie("session")
	u := User{}

	var UUID sql.NullString
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

	rows, err := tx.Query("SELECT username, uuid FROM users LIMIT $2", 999)
	if err != nil {
		http.Error(w, http.StatusText(500), 500)
		log.Fatal(err)
		return
	}

	defer rows.Close()

	for rows.Next() {

		err = rows.Scan(&u.Username, &UUID)

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

	tt, _ := BuildThread(1)

	tmpl.Execute(w, tt)

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
		emailQ := tx.QueryRow("SELECT * FROM users WHERE email = $2", email)
		usernameQ := tx.QueryRow("SELECT * FROM users WHERE username = $3", username)

		u := new(User)
		errE := emailQ.Scan(&u.Email)
		errU := usernameQ.Scan(&u.Username)
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
		stmt, err := tx.Prepare(`INSERT INTO users (email, username, password, uuid, session_switch) values (?,?,?,?,?)`)
		if err != nil {
			http.Error(w, http.StatusText(500), 500)
			log.Fatal(err)
		}
		res, err := stmt.Exec(email, username, hashAndSalt(password), 0, 0)
		if err != nil {
			tx.Rollback()
			http.Error(w, http.StatusText(500), 500)
			log.Fatal(err)
		}
		fmt.Println(res)
		fmt.Println(stmt)
		tx.Commit()
	}
	fmt.Fprint(w, "registered")
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
			fmt.Println("225")
			fmt.Println(err)
		}

		if (CheckSession(username)) == "1" {
			tx.Commit()
			fmt.Fprint(w, "Cannot login, session active elsewhere!")

			// http.Redirect(w, r, r.Header.Get("Referer"), 302)
			return
		}

		rows, err := tx.Query("SELECT username, password FROM users LIMIT $2", 999)
		if err != nil {
			fmt.Println("239")
			http.Error(w, http.StatusText(500), 500)
			log.Fatal(err)
			return
		}

		defer rows.Close()

		for rows.Next() {

			err = rows.Scan(&u.Username, &u.Password)
			if err != nil {
				fmt.Println("343")
				http.Error(w, http.StatusText(500), 500)
				log.Fatal(err)
				return
			}

			// get any error encountered during iteration
			err = rows.Err()
			if err != nil {
				fmt.Println("258")
				http.Error(w, http.StatusText(500), 500)
				log.Fatal(err)
				return
			}

			// checks if username matches input and compares hash password with input password
			if u.Username == username && (comparePasswords(u.Password, (password))) == true {

				u.UUID = genUUID()
				cookie = &http.Cookie{
					Name:   "session",
					Value:  u.UUID,
					MaxAge: 999999999999999999,
				}

				stmt, err := tx.Prepare("UPDATE users set uuid = ?, session_switch = ? WHERE username = ?")
				if err != nil {
					log.Fatal(err)
				}
				res, err := stmt.Exec(u.UUID, 1, username)
				if err != nil {
					tx.Rollback()
					log.Fatal(err)
				}
				// rowsAffected, _ := res.RowsAffected()
				// fmt.Println(w, "User %s created successfully (%d row affected)\n", u.uuid, rowsAffected)
				fmt.Println(res)
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
				tx.Rollback()
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

func CloseDB() error {
	return dB.Close()
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

func LookUpUsername(uuid string) string {
	// dB := Connect()
	// defer dB.Close()
	var username sql.NullString
	err := dB.QueryRow("SELECT username FROM users WHERE uuid=?", uuid).Scan(&username)
	if err != nil {
		log.Fatal()
	}
	return username.String
}

func LookUpUserID(uuid string) int16 {
	// dB := Connect()
	// defer dB.Close()
	var user_id sql.NullInt16
	err := dB.QueryRow("SELECT user_id FROM users WHERE uuid=?", uuid).Scan(&user_id)
	if err != nil {
		log.Fatal()
	}
	return user_id.Int16
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

func TimeDate() string {
	t := time.Now()
	return t.Format("2006-01-02 15:04:05")
}

// Get a single user given the UUID
func UserByUUID(uuid string) (u User) {
	var username string
	err := dB.QueryRow("SELECT username FROM users WHERE uuid=?", uuid).Scan(&u.User_ID, &u.Email, &u.Username, &u.Email, &u.Password)
	fmt.Println(username)
	if err != nil {
		fmt.Println("630")
		log.Fatal()
	}
	return
}

func ThreadByID(id int) (t Thread, err error) {
	t = Thread{}
	err = dB.QueryRow("SELECT thread_id, category, user_id, created_at FROM threads WHERE uuid = $1", id).
		Scan(&t.Thread_ID, &t.Category, &t.User_ID, &t.Created_At)
	return
}

func CreateThread(w http.ResponseWriter, r *http.Request) {
	// get cookie

	u := User{}

	// // var UUID sql.NullString
	// if r.Method != "POST" {
	// 	http.Error(w, http.StatusText(405), 405)
	// 	return
	// }

	// stmtFTT, err := dB.Prepare(`INSERT INTO threads (user_id, category, title, body, likes, img, created_at) values (?,?,?,?,?,?,?)`)
	// if err != nil {
	// 	log.Fatal(err)
	// }
	// // u := User{}
	// stmtFTT.Exec(u.FindUserID((CookieChecker(r, w))), r.FormValue("Category"), r.FormValue("Title"), "testing", 0, "img", TimeDate())
	tx, err := dB.Begin()
	if err != nil {
		fmt.Println(err)
	}

	stmt, err := tx.Prepare(`INSERT INTO threads (user_id, category, title, body, likes, img, created_at) values (?,?,?,?,?,?,?)`)
	if err != nil {
		http.Error(w, http.StatusText(500), 500)
		log.Fatal(err)
	}
	fmt.Println(CookieChecker(r,w))
	res, err := stmt.Exec(u.FindUserID((CookieChecker(r, w))), r.FormValue("Category"), r.FormValue("Title"), r.FormValue("Body"), 0, "img", TimeDate())
	fmt.Println(u.FindUserID(CookieChecker(r,w)))
	fmt.Println(r.FormValue("Category"))
	fmt.Println(r.FormValue("Title"), r.FormValue("Body"), 0, "img", TimeDate())
	

	if err != nil {
		tx.Rollback()
		http.Error(w, http.StatusText(500), 500)
		log.Fatal(err)
	}
	fmt.Println(res)
	fmt.Println(stmt)
	tx.Commit()
	http.Redirect(w, r, "/home", http.StatusSeeOther)

}

func NewPost(w http.ResponseWriter, r *http.Request) {
	u := User{}
	// t:= Thread{}
	// ID, err := strconv.Atoi(r.URL.Query().Get("id"))
	
	// thread, _ :=(BuildThread(ID))
	// var UUID sql.NullString
	if r.Method != "POST" {
		http.Error(w, http.StatusText(405), 405)
		return
	}
	// stmtFPT, err := dB.Prepare(`INSERT INTO posts (post_id ,thread_id, user_id, comment, likes, img, created_at) values (?,?,?,?,?,?,?)`)
	// if err != nil {
	// 	log.Fatal(err)
	// }
	// fmt.Println(t.Thread_ID)
	// stmtFPT.Exec(ID, t.Thread_ID, u.FindUserID((CookieChecker(r, w))), r.FormValue("Comment"), 0, "img", TimeDate())
	// fmt.Println("data inserted")
	// stmtFPT, err := dB.Prepare(`INSERT INTO posts (comment, likes, img, created_at) values (?,?,?,?)`)
	// if err != nil {
	// 	log.Fatal(err)
	// }
	// stmtFPT.Exec("testify", 0, "img", TimeDate())
	// fmt.Println("test")
	// tx, err := dB.Begin()
	// if err != nil {
	// 	fmt.Println(err)
	id := r.URL.Query().Get("id")
	ID, err := strconv.Atoi(id)
	if err != nil {
		http.Error(w, http.StatusText(500), 500)
		log.Fatal(err)
	}
	// thread, err := BuildThread(ID)
	// }
	tx, err := dB.Begin()
	if err != nil {
		fmt.Println(err)
	}
	stmt, err := tx.Prepare(`INSERT INTO posts (thread_id, user_id, comment, likes, img, created_at) values (?,?,?,?,?,?)`)
	if err != nil {
		http.Error(w, http.StatusText(500), 500)
		log.Fatal(err)
	}
	fmt.Println(CookieChecker(r,w))
	res, err := stmt.Exec(ID, u.FindUserID((CookieChecker(r, w))), r.FormValue("Comment"), 0, "img", TimeDate())
	
	fmt.Println(ID, u.FindUserID((CookieChecker(r, w))), r.FormValue("Comment"), 0, "img", TimeDate())

	if err != nil {
		tx.Rollback()
		http.Error(w, http.StatusText(500), 500)
		log.Fatal(err)
	}
	fmt.Println(res)
	fmt.Println(stmt)
	tx.Commit()
	t, err := template.ParseFiles("templates/posts.html", "templates/threads.html")
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		http.Error(w, err.Error(), 400)
		http.Error(w, "Bad Request-400", 400)
		return
	}
	posts,_:=BuildPosts(ID)
	
	t.ExecuteTemplate(w, "newpost", posts)
	// http.Redirect(w, r, "/thread/view?id=" + id, http.StatusSeeOther)

}

func (u User) FindUserID(uuid string) int {
	rows, err := dB.Query("SELECT user_id FROM users WHERE uuid =?", uuid)
	if err != nil {
		log.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		err = rows.Scan(&u.User_ID)
		if err != nil {
			log.Fatal(err)
		}
		// get any error encountered during iteration
		err = rows.Err()
		if err != nil {
			log.Fatal(err)
		}
	}
	return u.User_ID
}

func BuildThread(id int) (thread []Thread, err error) {
	tt := []Thread{}
	t := Thread{}

	test, err := dB.Query("SELECT * FROM threads")
	if err != nil {
		fmt.Println("196")
		log.Fatal(err)
		return
	}

	defer test.Close()
	for test.Next() {

		err = test.Scan(&t.Thread_ID, &t.User_ID, &t.Title, &t.Body, &t.Category, &t.Likes, &t.Img, &t.Created_At)
		if err != nil {
			fmt.Println("713")

			log.Fatal(err)
			return
		}
		tt = append(tt, t)

		// get any error encountered during iteration
		err = test.Err()
		if err != nil {
			fmt.Println("258")
			log.Fatal(err)
			return
		}

	}
	return tt, err

}

func BuildPosts(Thread_ID int) (post []Posts, err error) {
	pp := []Posts{}
	p := Posts{}

	test, err := dB.Query("SELECT * FROM posts")
	if err != nil {
		fmt.Println("196")
		log.Fatal(err)
		return
	}

	defer test.Close()
	for test.Next() {

		err = test.Scan(&p.Thread_ID, &p.Post_ID, &p.Comment, &p.User_ID, &p.Likes, &p.Img, &p.Created_At)
		if err != nil {
			fmt.Println("749")

			log.Fatal(err)
			return
		}
		pp = append(pp, p)

		// get any error encountered during iteration
		err = test.Err()
		if err != nil {
			fmt.Println("258")
			log.Fatal(err)
			return
		}

	}
	return pp, err

}
// func postThread(writer http.ResponseWriter, request *http.Request) {

// 		body := request.PostFormValue("body")
// 		id := request.PostFormValue("id")
// 		thread, err := ThreadByID(id)
// 		if err != nil {
// 			error_message(writer, request, "Cannot read thread")
// 		}
// 		if _, err := u.CreatePost(thread, body); err != nil {
// 			danger(err, "Cannot create post")
// 		}

// 	}
// }
func FindThreadID(id int) int16 {
	// dB := Connect()
	// defer dB.Close()
	var user_id sql.NullInt16
	err := dB.QueryRow("SELECT user_id FROM users WHERE uuid=?", id).Scan(&user_id)
	if err != nil {
		log.Fatal()
	}
	return user_id.Int16
}
func ViewThread(w http.ResponseWriter, r *http.Request) {

	ID, err := strconv.Atoi(r.URL.Query().Get("id"))
	if err != nil {
		http.Error(w, http.StatusText(500), 500)
		log.Fatal(err)
	}
	thread, err := BuildThread(ID)
	// for i:=range thread{
	// 	continue
	// }
	if err != nil {
		http.Error(w, http.StatusText(500), 500)
		log.Fatal(err)
	}
	parseTemplateFiles("threads").ExecuteTemplate(w, "threads.html", thread[ID-1])
}

func error_message(writer http.ResponseWriter, request *http.Request, msg string) {
	url := []string{"/err?msg=", msg}
	http.Redirect(writer, request, strings.Join(url, ""), 302)
}

func parseTemplateFiles(filenames ...string) (t *template.Template) {
	var files []string
	t = template.New("layout")
	for _, file := range filenames {
		files = append(files, fmt.Sprintf("templates/%s.html", file))
	}
	t = template.Must(t.ParseFiles(files...))
	return
}

func generateHTML(writer http.ResponseWriter, data interface{}, filenames ...string) {
	var files []string
	for _, file := range filenames {
		files = append(files, fmt.Sprintf("templates/%s.html", file))
	}

	templates := template.Must(template.ParseFiles(files...))
	templates.ExecuteTemplate(writer, "layout", data)
}

var logger *log.Logger

func danger(args ...interface{}) {
	logger.SetPrefix("ERROR ")
	logger.Println(args...)
}

// func returnUsername(ID int) string {

// }

func main() {
	Init()
	mux := http.NewServeMux()
	// CheckDBIntegrity()
	// dB.SetMaxOpenConns(1)
	fileServer := http.FileServer(http.Dir("templates")) // New code
	// mux.Handle("/static/", http.StripPrefix("/static/", fileServer))
	mux.Handle("/", fileServer)
	mux.HandleFunc("/home", Home)
	mux.HandleFunc("/register", Register)
	mux.HandleFunc("/login", Login)
	mux.HandleFunc("/logout", Logout)
	mux.HandleFunc("/thread/view", ViewThread)
	mux.HandleFunc("/thread/create", CreateThread)
	mux.HandleFunc("/thread/post", NewPost)
	fmt.Println("Listening on port 3000")
	server := &http.Server{
		Addr:    "localhost:3000",
		Handler: mux,
	}
	server.ListenAndServe()

	fmt.Println("Running code after ListenAndServe (only happens when server shuts down)")
}

// func noescape(str string) template.HTML {
// 	return template.HTML(str)
// }

// var fn = template.FuncMap{
// 	"noescape": noescape,
// }

// func CheckSessionHTTP(test func(w http.ResponseWriter, r *http.Request, s *User)) func(w http.ResponseWriter, r *http.Request) {

// 	return func(w http.ResponseWriter, r *http.Request) {
// 		session := CookieChecker(r, w)

// 		test(w, r, session)
// 	}
// }

func CookieChecker(r *http.Request, w http.ResponseWriter) string {
	cookie, err := r.Cookie("session")
	if err != nil {
		if err == http.ErrNoCookie {
			fmt.Fprint(w, "not logged in")

		}
	}
	return cookie.Value
}
