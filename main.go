package main

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"html/template"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/jmoiron/sqlx"
	"github.com/m0jik/recipe_website/internal/config"
	"github.com/m0jik/recipe_website/internal/sqlite"
	_ "github.com/mattn/go-sqlite3"
	"golang.org/x/crypto/argon2"
)

var tpl = template.Must(template.ParseGlob("templates/*.html"))

const cookieName = "session_id"

type App struct {
	DB  *sqlx.DB
	Cfg *config.Config
}

func main() {
	cfg, err := config.Load("config.json")
	if err != nil {
		log.Printf("config load error: %v", err)
		return
	}

	db, err := sqlite.New(cfg.DatabasePath)

	if err != nil {
		log.Printf("db open error: %v", err)
		return
	}
	defer db.Close()

	if err := sqlite.Migrate(db); err != nil {
		log.Printf("db init error: %v", err)
		return
	}

	app := &App{
		DB:  db,
		Cfg: cfg,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/v1", app.handleIndex) // Implement versioning
	mux.HandleFunc("/users/v1/register", app.handleRegister)
	mux.HandleFunc("/users/v1/login", app.handleLogin)
	mux.HandleFunc("/users/v1/logout", app.handleLogout)

	srv := &http.Server{
		Addr:    ":8080",
		Handler: mux,
	}

	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Printf("server error: %v", err)
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, os.Interrupt, syscall.SIGTERM)
	<-quit

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		log.Printf("server shutdown error: %v", err)
	}
}

func newUserLoginFunction(stuffTheFunctionNeeds string) http.HandlerFunc {
	return func(httpResponseWriter http.ResponseWriter, httpRequest *http.Request) {

	}
}

func hashPasswordArgon2id(password string) (string, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}

	memory := uint32(64 * 1024)
	iterations := uint32(3)
	parallelism := uint8(2)
	keyLen := uint32(32)

	hash := argon2.IDKey([]byte(password), salt, iterations, memory, parallelism, keyLen)

	encoded := base64.RawStdEncoding.EncodeToString(salt) + "$" + base64.RawURLEncoding.EncodeToString(hash)

	return encoded, nil
}

func verifyPasswordArgon2id(password, encoded string) bool {
	parts := strings.Split(encoded, "$")
	if len(parts) != 2 {
		return false
	}

	salt, err := base64.RawStdEncoding.DecodeString(parts[0])
	if err != nil {
		return false
	}

	expectedHash, err := base64.RawStdEncoding.DecodeString(parts[1])
	if err != nil {
		return false
	}

	memory := uint32(64 * 1024)
	iterations := uint32(3)
	parallelism := uint8(2)
	keyLen := uint32(32)

	actualHash := argon2.IDKey([]byte(password), salt, iterations, memory, parallelism, keyLen)

	return subtle.ConstantTimeCompare(actualHash, expectedHash) == 1
}

/*
func initDB(db *sql.DB) error {
	queries := []string{
		`CREATE TABLE IF NOT EXISTS usersV1 (
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
*/

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
		hash, err := hashPasswordArgon2id(pass)
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
		if !verifyPasswordArgon2id(pass, hash) {
			http.Error(w, "invalid credentials", http.StatusUnauthorized)
			return
		}
		sessionID, err := generateSessionID()
		if err != nil {
			http.Error(w, "server error", http.StatusInternalServerError)
			return
		}
		expires := time.Now().Add(time.Duration(a.Cfg.SessionLifetimeHours) * time.Hour)
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
