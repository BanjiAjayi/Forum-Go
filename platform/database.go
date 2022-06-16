package database

import (
	"database/sql"
	"log"
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
