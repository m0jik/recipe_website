package main

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"html/template"
	"log"
	"net/http"
	"time"

	_ "github.com/mattn/go-sqlite3"
	"golang.org/x/crypto/bcrypt"
)

var tpl = template.Must(template.ParseGlob("templates/*.html"))

const cookieName = "session_id"

type App struct {
	DB *sql.DB
}

func main() {
	db, err := sql.Open("sqlite3", "./app.db")
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	if err := initDB(db); err != nil {
		log.Fatal(err)
	}

	app := &App{DB: db}

	http.HandleFunc("/", app.handleIndex)
	http.HandleFunc("/register", app.handleRegister)
	http.HandleFunc("/login", app.handleLogin)
	http.HandleFunc("/logout", app.handleLogout)
	log.Println("Listening on :8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}

func initDB(db *sql.DB) error {
	queries := []string{
		`CREATE TABLE IF NOT EXISTS users (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			username TEXT NOT NULL UNIQUE,
			password_hash TEXT NOT NULL,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP
		);`,
		`CREATE TABLE IF NOT EXISTS sessions (
			id TEXT PRIMARY KEY,
			user_id INTEGER NOT NULL,
			expires_at DATETIME NOT NULL,
			FOREIGN KEY(user_id) REFERENCES users(id)
		);`,
	}
	for _, q := range queries {
		if _, err := db.Exec(q); err != nil {
			return err
		}
	}
	return nil
}

func (a *App) handleIndex(w http.ResponseWriter, r *http.Request) {
	username := ""
	if uid, ok := a.getUserIDFromSession(r); ok {
		row := a.DB.QueryRow("SELECT username FROM users WHERE id = ?", uid)
		_ = row.Scan(&username)
	}
	tpl.ExecuteTemplate(w, "index.html", map[string]interface{}{
		"Username": username,
	})
}

func (a *App) handleRegister(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		tpl.ExecuteTemplate(w, "register.html", nil)
		return
	case http.MethodPost:
		if err := r.ParseForm(); err != nil {
			http.Error(w, "invalid form", http.StatusBadRequest)
			return
		}
		username := r.FormValue("username")
		pass := r.FormValue("password")
		if username == "" || pass == "" {
			http.Error(w, "username and password required", http.StatusBadRequest)
			return
		}
		hash, err := bcrypt.GenerateFromPassword([]byte(pass), bcrypt.DefaultCost)
		if err != nil {
			http.Error(w, "server error", http.StatusInternalServerError)
			return
		}
		_, err = a.DB.Exec("INSERT INTO users(username, password_hash) VALUES (?, ?)", username, string(hash))
		if err != nil {
			http.Error(w, "could not create user", http.StatusInternalServerError)
			return
		}
		http.Redirect(w, r, "/login", http.StatusSeeOther)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (a *App) handleLogin(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		tpl.ExecuteTemplate(w, "login.html", nil)
		return
	case http.MethodPost:
		if err := r.ParseForm(); err != nil {
			http.Error(w, "invalid form", http.StatusBadRequest)
			return
		}
		username := r.FormValue("username")
		pass := r.FormValue("password")
		var id int
		var hash string
		row := a.DB.QueryRow("SELECT id, password_hash FROM users WHERE username = ?", username)
		if err := row.Scan(&id, &hash); err != nil {
			http.Error(w, "invalid credentials", http.StatusUnauthorized)
			return
		}
		if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(pass)); err != nil {
			http.Error(w, "invalid credentials", http.StatusUnauthorized)
			return
		}
		sessionID, err := generateSessionID()
		if err != nil {
			http.Error(w, "server error", http.StatusInternalServerError)
			return
		}
		expires := time.Now().Add(24 * time.Hour)
		_, err = a.DB.Exec("INSERT INTO sessions(id, user_id, expires_at) VALUES (?, ?, ?)", sessionID, id, expires.Format(time.RFC3339))
		if err != nil {
			http.Error(w, "server error", http.StatusInternalServerError)
			return
		}
		c := &http.Cookie{
			Name:     cookieName,
			Value:    sessionID,
			Path:     "/",
			HttpOnly: true,
			Secure:   false, // set true when using HTTPS
			Expires:  expires,
		}
		http.SetCookie(w, c)
		http.Redirect(w, r, "/", http.StatusSeeOther)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (a *App) handleLogout(w http.ResponseWriter, r *http.Request) {
	c, err := r.Cookie(cookieName)
	if err == nil {
		a.DB.Exec("DELETE FROM sessions WHERE id = ?", c.Value)
		http.SetCookie(w, &http.Cookie{
			Name:     cookieName,
			Value:    "",
			Path:     "/",
			HttpOnly: true,
			MaxAge:   -1,
		})
	}
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (a *App) getUserIDFromSession(r *http.Request) (int, bool) {
	c, err := r.Cookie(cookieName)
	if err != nil {
		return 0, false
	}
	var userID int
	var expiresStr string
	row := a.DB.QueryRow("SELECT user_id, expires_at FROM sessions WHERE id = ?", c.Value)
	if err := row.Scan(&userID, &expiresStr); err != nil {
		return 0, false
	}
	exp, err := time.Parse(time.RFC3339, expiresStr)
	if err != nil {
		return userID, true
	}
	if time.Now().After(exp) {
		a.DB.Exec("DELETE FROM sessions WHERE id = ?", c.Value)
		return 0, false
	}
	return userID, true
}

func generateSessionID() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
