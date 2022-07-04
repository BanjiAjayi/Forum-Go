package structs

import (
	"database/sql"

	// "text/template"

	_ "github.com/mattn/go-sqlite3"
)

type User struct {
	User_ID  int    `dB:"user_id"`
	Email    string `dB:"email"`
	Username string
	Password string
	UUID     string
}

type Thread struct {
	Thread_ID  int `dB:"thread_id"`
	User_ID    sql.NullString
	Title      string `dB:"title"`
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
	CreatedAt string
}
