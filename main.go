package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"html/template"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/jmoiron/sqlx"
	"github.com/m0jik/recipe_website/internal/config"
	"github.com/m0jik/recipe_website/internal/services"
	"github.com/m0jik/recipe_website/internal/sqlite"
	"golang.org/x/crypto/argon2"
)

var tpl = template.Must(template.New("templates").Funcs(template.FuncMap{
	"urlquery": url.QueryEscape,
	"tagurl":   tagURL,
	"hastag":   hasTag,
}).ParseGlob("templates/*.html"))

const cookieName = "session_id"

type App struct {
	DB       *sqlx.DB
	Cfg      *config.Config
	Users    *services.UserService
	Recipes  *services.RecipeService
	Email    services.EmailSender
	Images   *services.ImageService
	Shopping *services.ShoppingListService
	Pantry   *services.PantryService
}

type PageData struct {
	Username        string
	Recipes         []services.RecipeInfo
	Query           string
	SelectedTags    []string
	MaxTime         int
	PresetTagGroups []services.PresetTagGroup
}

type RecipePageData struct {
	PageData

	RecipeID        int64
	Added           bool
	Title           string
	Description     string
	ImageURL        string
	Ingredients     []services.Ingredient
	Steps           []services.Step
	CreatorUsername string
	Servings        int
	PrepTimeMinutes int
	Tags            []string
}

type PageOneData struct {
	PageData

	Title       string
	Description string
	Servings    int
	PrepTime    int
}

type PageTwoData struct {
	PageData

	Image       string
	Title       string
	Description string
	Tags        []string
	Servings    string
	PrepTime    string
	Ingredients []services.Ingredient
	Steps       []services.Step
}

func main() {
	log.Println("Loading config...")
	cfg, err := config.Load("config.json")
	log.Println("Config loaded.")
	if err != nil {
		log.Printf("config load error: %v", err)
		return
	}

	log.Println("Opening DB...")
	db, err := sqlite.New(cfg.DatabasePath)
	log.Println("DB opened.")

	if err != nil {
		log.Printf("db open error: %v", err)
		return
	}

	// defer db.Close()
	defer func() {
		if err := db.Close(); err != nil {
			log.Println("Error closing DB:", err)
		}
	}()

	log.Println("Running migrations...")
	if err := sqlite.Migrate(db); err != nil {
		log.Printf("db init error: %v", err)
		return
	}
	log.Println("Migrations complete.")

	emailSender, err := buildEmailSender(cfg)
	if err != nil {
		log.Printf("email setup error: %v", err)
		return
	}

	app := &App{
		DB:       db,
		Cfg:      cfg,
		Users:    services.NewUserService(db),
		Recipes:  services.NewRecipeService(db),
		Email:    emailSender,
		Images:   services.NewImageService(&services.LocalStore{Dir: "uploads"}),
		Shopping: services.NewShoppingListService(db),
		Pantry:   services.NewPantryService(db),
	}

	log.Println("Setting up handlers...")
	mux := http.NewServeMux()
	mux.HandleFunc("/v1", app.handleIndex) // Implement versioning
	mux.HandleFunc("/users/v1/register", app.handleRegister)
	mux.HandleFunc("/users/v1/login", app.handleLogin)
	mux.HandleFunc("/users/v1/logout", app.handleLogout)
	mux.HandleFunc("/users/v1/request_reset", app.handleRequestReset)
	mux.HandleFunc("/users/v1/reset", app.handleReset)
	mux.HandleFunc("/users/v1/verify", app.handleVerifyEmail)

	// Recipe
	mux.HandleFunc("/recipes/v1/new", app.createNewRecipe)
	mux.HandleFunc("/recipes/v1/ingredient-row", app.handleIngredientRows)
	mux.HandleFunc("/recipes/v1/step-row", app.handleStepRow)
	mux.HandleFunc("/recipes/v1/tag-row", app.handleTagRows)
	mux.HandleFunc("/recipes/v1/submit", app.handleSubmit)
	mux.HandleFunc("/recipes/v1/myRecipe", app.handleMyRecipes)
	mux.HandleFunc("/recipes/v1/", app.handleRecipe)

	//Shopping List
	mux.HandleFunc("GET /shopping-list/v1", app.handleShoppingList)
	mux.HandleFunc("POST /shopping-list/v1/add", app.handleShoppingListAdd)
	mux.HandleFunc("DELETE /shopping-list/v1/remove", app.handleShoppingListRemove)
	mux.HandleFunc("DELETE /shopping-list/v1/remove-recipe", app.handleShoppingListRemoveRecipe)
	mux.HandleFunc("POST /shopping-list/v1/check", app.handleShoppingListCheck)
	mux.HandleFunc("POST /shopping-list/v1/check-all", app.handleShoppingListCheckAll)
	mux.HandleFunc("POST /shopping-list/v1/qty", app.handleShoppingListQty)
	mux.HandleFunc("POST /shopping-list/v1/filter", app.handleShoppingListFilter)
	mux.HandleFunc("POST /shopping-list/v1/to-pantry", app.handleShoppingListToPantry)

	//Pantry
	mux.HandleFunc("POST /pantry/v1/add", app.handlePantryAdd)
	mux.HandleFunc("DELETE /pantry/v1/remove", app.handlePantryRemove)
	mux.HandleFunc("GET /pantry/v1/{$}", app.handlePantry)

	// path
	mux.Handle("/uploads/", http.StripPrefix("/uploads/", http.FileServer(http.Dir("uploads"))))

	// Css
	mux.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir("static"))))

	mux.HandleFunc("/", app.handleIndex)
	log.Println("Handlers set up.")

	srv := &http.Server{
		Addr:    ":8080",
		Handler: mux,
	}

	log.Println("Starting server goroutine...")
	go func() {
		log.Println("Calling ListenAndServe...")
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Printf("server error: %v", err)
		}
		log.Println("ListenAndServe successfully called.")
	}()
	log.Println("Server goroutine started.")

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, os.Interrupt, syscall.SIGTERM)
	<-quit

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	log.Println("Waiting for shutdown signal...")
	if err := srv.Shutdown(ctx); err != nil {
		log.Printf("server shutdown error: %v", err)
	}
}

func buildEmailSender(cfg *config.Config) (services.EmailSender, error) {
	switch strings.ToLower(cfg.Email.Provider) {
	case "", "smtp":
		return services.NewSMTPEmail(
			cfg.Email.SMTP.Host,
			cfg.Email.SMTP.Port,
			cfg.Email.SMTP.From,
			cfg.Email.SMTP.Password,
		), nil
	// case "noop":
	// 	return services.NoopEmail{}, nil
	default:
		return nil, errors.New("unsupported email provider: " + cfg.Email.Provider)
	}
}

// func newUserLoginFunction(stuffTheFunctionNeeds string) http.HandlerFunc {
// 	return func(httpResponseWriter http.ResponseWriter, httpRequest *http.Request) {

// 	}
// }

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

	encoded := base64.RawStdEncoding.EncodeToString(salt) + "$" + base64.RawStdEncoding.EncodeToString(hash)

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
		// row := a.DB.QueryRow("SELECT username FROM usersV1 WHERE id = ?", uid)
		// if err := row.Scan(&username); err != nil {
		// 	username = ""
		// }
		u, err := a.Users.GetUsernameByID(uid)
		if err != nil {
			http.Error(w, "Invalid session", http.StatusInternalServerError)
			return
		}
		username = u
	}

	query := r.URL.Query().Get("query")
	tags := normalizeTagFilters(r.URL.Query()["tag"])
	maxTime, _ := strconv.Atoi(r.URL.Query().Get("max_time"))
	if maxTime < 0 {
		maxTime = 0
	}

	var recipes []services.RecipeInfo
	var err error

	if query != "" || len(tags) > 0 || maxTime > 0 {
		recipes, err = a.Recipes.Search(query, tags, maxTime) // filtered results
	} else {
		recipes, err = a.Recipes.GetAllRecipes() // all recipes
	}

	if err != nil {
		log.Printf("Error loading recipes: %v", err)
		http.Error(w, "Failed to load recipes", http.StatusInternalServerError)
		return
	}

	data := PageData{
		Username:        username,
		Recipes:         recipes,
		Query:           query,
		SelectedTags:    tags,
		MaxTime:         maxTime,
		PresetTagGroups: services.PresetTagGroups,
	}

	err = tpl.ExecuteTemplate(w, "index.html", data)

	if err != nil {
		log.Printf("Error rendering index template: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
}

func normalizeTagFilters(tags []string) []string {
	result := make([]string, 0, len(tags))
	seen := make(map[string]struct{})
	for _, tag := range tags {
		tag = strings.ToLower(strings.TrimSpace(tag))
		if tag == "" {
			continue
		}
		if _, exists := seen[tag]; exists {
			continue
		}
		seen[tag] = struct{}{}
		result = append(result, tag)
	}
	return result
}

func hasTag(tag string, selected []string) bool {
	for _, selectedTag := range selected {
		if tag == selectedTag {
			return true
		}
	}
	return false
}

func tagURL(tag string, selected []string, query string) string {
	values := url.Values{}
	if query != "" {
		values.Set("query", query)
	}

	removed := false
	for _, selectedTag := range selected {
		if selectedTag == tag {
			removed = true
			continue
		}
		values.Add("tag", selectedTag)
	}
	if !removed {
		values.Add("tag", tag)
	}
	if values.Encode() == "" {
		return "/"
	}
	return "/?" + values.Encode()
}

func (a *App) handleRegister(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		PageData := PageData{
			PresetTagGroups: services.PresetTagGroups,
		}
		err := tpl.ExecuteTemplate(w, "register.html", PageData)
		if err != nil {
			log.Printf("Error rendering register template: %v", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}
		return
	case http.MethodPost:
		if err := r.ParseForm(); err != nil {
			http.Error(w, "invalid form", http.StatusBadRequest)
			return
		}
		username := r.FormValue("username")
		email := normalizeEmail(r.FormValue("email"))
		pass := r.FormValue("password")
		confirmPass := r.FormValue("confirm_password")
		if pass != confirmPass {
			http.Error(w, "passwords do not match", http.StatusBadRequest)
			return
		}
		if username == "" || pass == "" || email == "" || confirmPass == "" {
			http.Error(w, "username, email, password, and confirm password required", http.StatusBadRequest)
			return
		}
		if !a.Users.ValidPassword(pass) {
			http.Error(w, "password must be at least 8 characters and contain a number, uppercase letter, and lowercase letter", http.StatusBadRequest)
			return
		}
		if !strings.Contains(email, "@") {
			http.Error(w, "invalid email", http.StatusBadRequest)
			return
		}
		hash, err := hashPasswordArgon2id(pass)
		if err != nil {
			http.Error(w, "server error", http.StatusInternalServerError)
			return
		}
		// _, err = a.DB.Exec("INSERT INTO usersV1(username, password_hash) VALUES (?, ?)", username, string(hash))
		// if err := a.Users.CreateUser(username, email, hash); err != nil {
		// 	http.Error(w, "could not create user", http.StatusInternalServerError)
		// 	return
		// }

		userID, err := a.Users.CreateUser(username, email, hash)
		if err != nil {
			if errors.Is(err, services.ErrUserExists) {
				http.Error(w, "username already taken", http.StatusBadRequest)
				return
			}
			http.Error(w, "could not create user", http.StatusInternalServerError)
			return
		}

		token, err := generateSessionID()
		if err != nil {
			http.Error(w, "server error", http.StatusInternalServerError)
			return
		}

		expires := time.Now().Add(24 * time.Hour)

		err = a.Users.CreateEmailVerification(userID, token, expires.Format(time.RFC3339))
		if err != nil {
			http.Error(w, "could not create email verification", http.StatusInternalServerError)
			return
		}

		verifyLink := a.Cfg.BaseURL + "/users/v1/verify?token=" + token

		go func() {
			body, err := buildVerificationEmail(username, verifyLink)
			if err != nil {
				log.Printf("email template render failed for %s: %v", email, err)
				body = "Verify your account: " + verifyLink
			}
			err = a.Email.Send(email, "Verify your account", body)
			if err != nil {
				log.Printf("email send failed to %s: %v", email, err)
			}
		}()

		http.Redirect(w, r, "/users/v1/login", http.StatusSeeOther)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (a *App) handleLogin(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		PageData := PageData{
			PresetTagGroups: services.PresetTagGroups,
		}
		err := tpl.ExecuteTemplate(w, "login.html", PageData)
		if err != nil {
			log.Printf("Error rendering login template: %v", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}
		return
	case http.MethodPost:
		if err := r.ParseForm(); err != nil {
			http.Error(w, "invalid form", http.StatusBadRequest)
			return
		}
		email := normalizeEmail(r.FormValue("email"))
		pass := r.FormValue("password")
		var id int
		var hash string
		// row := a.DB.QueryRow("SELECT id, password_hash FROM usersV1 WHERE username = ?", username)

		id, hash, err := a.Users.GetUserCredentials(email)
		if err != nil {
			http.Error(w, "Invalid credentials", http.StatusUnauthorized)
			return
		}

		//if err := row.Scan(&id, &hash); err != nil {
		//	http.Error(w, "invalid credentials", http.StatusUnauthorized)
		//	return
		//}
		if !verifyPasswordArgon2id(pass, hash) {
			http.Error(w, "invalid credentials", http.StatusUnauthorized)
			return
		}

		verified, _ := a.Users.IsUserVerified(id)
		if !verified {
			http.Error(w, "please verify your email", http.StatusForbidden)
			return
		}

		sessionID, err := generateSessionID()
		if err != nil {
			http.Error(w, "could not generate session ID", http.StatusInternalServerError)
			return
		}
		expires := time.Now().Add(time.Duration(a.Cfg.SessionLifetimeHours) * time.Hour) // Uses session lifetime set in config.go
		//_, err = a.DB.Exec("INSERT INTO sessionsV1(id, user_id, expires_at) VALUES (?, ?, ?)", sessionID, id, expires.Format(time.RFC3339))

		if err := a.Users.CreateSession(sessionID, id, expires.Format(time.RFC3339)); err != nil {
			http.Error(w, "could not create session", http.StatusInternalServerError)
			return
		}

		//if err != nil {
		//	http.Error(w, "server error", http.StatusInternalServerError)
		//	return
		//}
		c := &http.Cookie{
			Name:     cookieName,
			Value:    sessionID,
			Path:     "/",
			HttpOnly: true,
			Secure:   false, // set true when using HTTPS
			Expires:  expires,
		}
		http.SetCookie(w, c)
		http.Redirect(w, r, "/v1", http.StatusSeeOther)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (a *App) handleLogout(w http.ResponseWriter, r *http.Request) {
	c, err := r.Cookie(cookieName)
	if err == nil {
		// a.DB.Exec("DELETE FROM sessionsV1 WHERE id = ?", c.Value)

		if err := a.Users.DeleteSession(c.Value); err != nil {
			http.Error(w, "could not delete session", http.StatusInternalServerError)
			return
		}

		http.SetCookie(w, &http.Cookie{
			Name:     cookieName,
			Value:    "",
			Path:     "/",
			HttpOnly: true,
			MaxAge:   -1,
		})
	}
	http.Redirect(w, r, "/v1", http.StatusSeeOther)
}

func (a *App) handleRequestReset(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		PageData := PageData{
			PresetTagGroups: services.PresetTagGroups,
		}
		err := tpl.ExecuteTemplate(w, "request_reset.html", PageData)
		if err != nil {
			log.Printf("Error rendering request_reset template: %v", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		return
	case http.MethodPost:
		if err := r.ParseForm(); err != nil {
			http.Error(w, "invalid form", http.StatusBadRequest)
			return
		}
		email := normalizeEmail(r.FormValue("email"))
		// var id int
		// row := a.DB.QueryRow("SELECT id FROM usersV1 WHERE username = ?", username)
		// if err := row.Scan(&id); err != nil {
		//  	http.Error(w, "user not found", http.StatusNotFound)
		//  	return
		// }
		id, err := a.Users.GetUserIDByEmail(email)
		if err != nil {
			http.Error(w, "user not found", http.StatusNotFound)
			return
		}
		token, err := generateToken()
		if err != nil {
			http.Error(w, "server error", http.StatusInternalServerError)
			return
		}
		expires := time.Now().Add(15 * time.Minute)
		// _, err = a.DB.Exec("INSERT INTO passResetV1(user_id, token, expires_at) VALUES (?, ?, ?)", id, token, expires.Format(time.RFC3339))
		// if err != nil {
		//	  http.Error(w, "server error", http.StatusInternalServerError)
		//	  return
		// }
		if err := a.Users.CreatePasswordReset(id, token, expires.Format(time.RFC3339)); err != nil {
			http.Error(w, "server error", http.StatusInternalServerError)
			return
		}
		resetLink := a.Cfg.BaseURL + "/users/v1/reset?token=" + token
		// w.Write([]byte("Reset link: " + resetLink))
		go func() {
			body, err := buildPasswordResetEmail(resetLink)
			if err != nil {
				log.Printf("email template render failed for %s: %v", email, err)
				body = "Reset your password: " + resetLink
			}
			err = a.Email.Send(email, "Password Reset Request", body)
			if err != nil {
				log.Printf("email send failed to %s: %v", email, err)
			}
		}()
		http.Redirect(w, r, "/users/v1/login", http.StatusSeeOther)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (a *App) handleReset(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		token := r.URL.Query().Get("token")
		err := tpl.ExecuteTemplate(w, "reset.html", map[string]string{"Token": token})
		if err != nil {
			log.Printf("Error rendering reset template: %v", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		return
	case http.MethodPost:
		if err := r.ParseForm(); err != nil {
			http.Error(w, "invalid form", http.StatusBadRequest)
			return
		}
		token := r.FormValue("token")
		newPassword := r.FormValue("password")
		confirmPassword := r.FormValue("confirm_password")
		if token == "" || newPassword == "" || confirmPassword == "" {
			http.Error(w, "token and new password required", http.StatusBadRequest)
			return
		}
		if newPassword != confirmPassword {
			http.Error(w, "passwords do not match", http.StatusBadRequest)
			return
		}
		if !a.Users.ValidPassword(newPassword) {
			http.Error(w, "password must be at least 8 characters and contain a number, uppercase letter, and lowercase letter", http.StatusBadRequest)
			return
		}
		// var id int
		// var expiresStr string
		// row := a.DB.QueryRow("SELECT user_id, expires_at FROM passResetV1 WHERE token = ?", token)
		// if err := row.Scan(&id, &expiresStr); err != nil {
		// 	http.Error(w, "user not found", http.StatusNotFound)
		// 	return
		// }
		id, expiresStr, err := a.Users.GetPasswordReset(token)
		if err != nil {
			http.Error(w, "invalid token", http.StatusNotFound)
			return
		}
		exp, err := time.Parse(time.RFC3339, expiresStr)
		if err != nil || time.Now().After(exp) {
			http.Error(w, "token expired", http.StatusUnauthorized)
			return
		}
		hash, err := hashPasswordArgon2id(newPassword)
		if err != nil {
			http.Error(w, "server error", http.StatusInternalServerError)
			return
		}
		// _, err = a.DB.Exec("UPDATE usersV1 SET password_hash = ? WHERE id = ?", hash, id)
		// if err != nil {
		//  	http.Error(w, "server error", http.StatusInternalServerError)
		//  	return
		// }
		if err := a.Users.UpdatePassword(id, hash); err != nil {
			http.Error(w, "server error", http.StatusInternalServerError)
			return
		}
		// _, err = a.DB.Exec("DELETE FROM passResetV1 WHERE token = ?", token)
		// if err != nil {
		//  	http.Error(w, "server error", http.StatusInternalServerError)
		//  	return
		// }
		if err := a.Users.DeletePasswordReset(token); err != nil {
			http.Error(w, "server error", http.StatusInternalServerError)
			return
		}
		http.Redirect(w, r, "/users/v1/login", http.StatusSeeOther)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (a *App) getUserIDFromSession(r *http.Request) (int, bool) {
	c, err := r.Cookie(cookieName)
	if err != nil {
		return 0, false
	}

	var userID int
	var expiresStr string
	//err = a.DB.QueryRow(
	//	"SELECT user_id, expires_at FROM sessionsV1 WHERE id = ?",
	//	c.Value,
	//).Scan(&userID, &expiresStr)

	userID, expiresStr, err = a.Users.GetUserID(c.Value)
	if err != nil {
		return 0, false
	}

	exp, err := time.Parse(time.RFC3339, expiresStr)
	if err != nil {
		// a.DB.Exec("DELETE FROM sessionsV1 WHERE id = ?", c.Value)
		log.Printf("Initial error: %v", err)
		err = a.Users.DeleteSession(c.Value)
		if err != nil {
			log.Printf("Error deleting session: %v", err)
		}
		return 0, false
	}

	if time.Now().After(exp) {
		// a.DB.Exec("DELETE FROM sessionsV1 WHERE id = ?", c.Value)
		err := a.Users.DeleteSession(c.Value)
		if err != nil {
			log.Printf("Error deleting session: %v", err)
		}
		return 0, false
	}

	return userID, true
}

func generateSessionID() (string, error) { // sessions only
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func (a *App) handleMyRecipes(w http.ResponseWriter, r *http.Request) {
	userID, ok := a.getUserIDFromSession(r)
	if !ok {
		http.Redirect(w, r, "/users/v1/login", http.StatusSeeOther)
		return
	}
	recipes, err := a.Recipes.GetRecipesByUser(userID)
	if err != nil {
		http.Error(w, "could not load recipes", http.StatusInternalServerError)
		return
	}

	username, err := a.Users.GetUsernameByID(userID)
	if err != nil {
		log.Printf("Error getting username for user ID %d: %v", userID, err)
		http.Error(w, "could not load user info", http.StatusInternalServerError)
		return
	}

	data := PageData{
		Username:        username,
		Recipes:         recipes,
		PresetTagGroups: services.PresetTagGroups,
	}

	err = tpl.ExecuteTemplate(w, "myRecipes.html", data)

	if err != nil {
		log.Printf("Error rendering template: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
}

func (a *App) createNewRecipe(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		username := ""
		if uid, ok := a.getUserIDFromSession(r); ok {
			u, err := a.Users.GetUsernameByID(uid)
			if err != nil {
				http.Error(w, "Invalid session", http.StatusInternalServerError)
				return
			}
			username = u
		}

		data := PageOneData{
			PageData: PageData{
				Username:        username,
				PresetTagGroups: services.PresetTagGroups,
			},
		}

		err := tpl.ExecuteTemplate(w, "pageOne.html", data)

		if err != nil {
			log.Printf("Error rendering pageOne template: %v", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}
	case http.MethodPost:
		a.handleNewRecipePost(w, r)
	}
}

func (a *App) handleNewRecipePost(w http.ResponseWriter, r *http.Request) {
	username := ""
	if uid, ok := a.getUserIDFromSession(r); ok {
		u, err := a.Users.GetUsernameByID(uid)
		if err != nil {
			http.Error(w, "Invalid session", http.StatusInternalServerError)
			return
		}
		username = u
	}

	if err := r.ParseMultipartForm(32 << 20); err != nil {
		http.Error(w, "could not parse form", http.StatusBadRequest)
		return
	}

	var imagePath string

	file, header, err := r.FormFile("myfile")
	if err == nil {
		defer func() {
			if err := file.Close(); err != nil {
				log.Println("Error closing file:", err)
			}
		}()
		imagePath, err = a.Images.Process(file, header)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
	}

	pageData := PageTwoData{
		PageData: PageData{
			Username:        username,
			PresetTagGroups: services.PresetTagGroups,
		},

		Title:       r.FormValue("title"),
		Description: r.FormValue("description"),
		Image:       imagePath,
		Tags:        r.Form["tags"],
		Servings:    r.FormValue("servings"),
		PrepTime:    r.FormValue("prep_time_minutes"),
	}

	err = tpl.ExecuteTemplate(w, "pageTwo.html", pageData)

	if err != nil {
		log.Printf("Error rendering pageTwo template: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
}

func (a *App) handleIngredientRows(w http.ResponseWriter, r *http.Request) {
	err := tpl.ExecuteTemplate(w, "ingredient-row", map[string]string{
		"Qty":  r.URL.Query().Get("qty"),
		"Unit": r.URL.Query().Get("unit"),
		"Name": r.URL.Query().Get("name"),
	})
	if err != nil {
		log.Printf("Error rendering ingredient row: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
}

func (a *App) handleStepRow(w http.ResponseWriter, r *http.Request) {
	err := tpl.ExecuteTemplate(w, "step-row", map[string]string{
		"Instruction": r.URL.Query().Get("step"),
		"Note":        r.URL.Query().Get("note"),
	})
	if err != nil {
		log.Printf("Error rendering step row: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
}

func (a *App) handleTagRows(w http.ResponseWriter, r *http.Request) {
	tag := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("tag")))
	for _, presetTag := range services.PresetTags {
		if tag == presetTag {
			err := tpl.ExecuteTemplate(w, "tag-row", map[string]string{"Tag": tag})
			if err != nil {
				log.Printf("Error rendering tag row: %v", err)
				http.Error(w, "Error rendering tag row", http.StatusInternalServerError)
			}
			return
		}
	}
	if tag != "" {
		http.Error(w, "invalid tag", http.StatusBadRequest)
	}
}

func (a *App) handleSubmit(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPost:
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if err := r.ParseForm(); err != nil {
			http.Error(w, "could not parse form", http.StatusBadRequest)
			return
		}

		userID, ok := a.getUserIDFromSession(r)
		if !ok {
			http.Error(w, "not logged in", http.StatusUnauthorized)
			return
		}

		servings, _ := strconv.Atoi(r.FormValue("servings"))
		prepTimeMinutes, _ := strconv.Atoi(r.FormValue("prep_time_minutes"))

		// needs to be fixed becasue
		// - bachSaveIngredients and BatchSaveSteps commits the instant it runs (no transaction wrapping any of this)
		recipeID, err := a.Recipes.CreateRecipe(userID, r.FormValue("title"), r.FormValue("image"), r.FormValue("description"), servings, prepTimeMinutes)
		if err != nil {
			http.Error(w, "could not create recipe", http.StatusInternalServerError)
			return
		}
		if err := a.Recipes.SaveTags(recipeID, strings.Join(r.Form["tags"], ",")); err != nil {
			http.Error(w, "could not save tags", http.StatusInternalServerError)
			return
		}

		versionID, err := a.Recipes.GetLatestVersionID(recipeID)
		if err != nil {
			http.Error(w, "could not get version", http.StatusInternalServerError)
			return
		}

		// fails partway through ( some ingredients row may already be commited)
		if err := a.Recipes.BatchSaveIngredients(versionID, r.Form["ingredient_name"], r.Form["ingredient_qty"], r.Form["ingredient_unit"]); err != nil {
			http.Error(w, "could not save ingredients", http.StatusInternalServerError)
			return
		}
		if err := a.Recipes.BatchSaveSteps(versionID, r.Form["step_instruction"], r.Form["step_note"]); err != nil {
			http.Error(w, "could not save steps", http.StatusInternalServerError)
			return
		}

		http.Redirect(w, r, "/v1", http.StatusSeeOther)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (a *App) handleVerifyEmail(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		token := r.URL.Query().Get("token")
		if token == "" {
			http.Error(w, "token required", http.StatusBadRequest)
			return
		}
		err := a.Users.VerifyEmail(token)
		if err != nil {
			http.Error(w, "invalid or expired token", http.StatusBadRequest)
			return
		}
		err = a.Users.DeleteEmailVerification(token)
		if err != nil {
			http.Error(w, "server error", http.StatusInternalServerError)
			return
		}
		http.Redirect(w, r, "/users/v1/login", http.StatusSeeOther)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (a *App) handleRecipe(w http.ResponseWriter, r *http.Request) {
	username := ""
	sessionUserID, loggedIn := a.getUserIDFromSession(r)
	if loggedIn {
		u, err := a.Users.GetUsernameByID(sessionUserID)
		if err != nil {
			http.Error(w, "Invalid session", http.StatusInternalServerError)
			return
		}
		username = u
	}
	idStr := strings.TrimPrefix(r.URL.Path, "/recipes/v1/")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		http.NotFound(w, r)
		return
	}

	data, recipeOwnerID, err := a.Recipes.GetRecipeForView(id)
	if err != nil {
		http.Error(w, "Recipe not found", http.StatusNotFound)
		return
	}

	added := false
	if loggedIn {
		added, err = a.Shopping.HasRecipe(sessionUserID, id)
		if err != nil {
			log.Printf("Error checking shopping list for recipe %d: %v", id, err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}
	}

	creatorusername, err := a.Users.GetUsernameByID(int(recipeOwnerID))
	if err != nil {
		creatorusername = "Unknown"
	}

	pageData := RecipePageData{
		PageData: PageData{
			Username:        username,
			PresetTagGroups: services.PresetTagGroups,
		},

		RecipeID:        id,
		Added:           added,
		Title:           data.Recipe.Title,
		Description:     data.Recipe.Description,
		ImageURL:        data.Recipe.ImageURL,
		Ingredients:     data.Ingredients,
		Steps:           data.Steps,
		CreatorUsername: creatorusername,
		Servings:        data.Recipe.Servings,
		PrepTimeMinutes: data.Recipe.PrepTimeMinutes,
		Tags:            data.Recipe.Tags,
	}

	var buf bytes.Buffer
	err = tpl.ExecuteTemplate(&buf, "recipe.html", pageData)
	if err != nil {
		log.Printf("Error rendering recipe template: %v", err)
		http.Error(w, "Template error", http.StatusInternalServerError)
		return
	}
	w.Write(buf.Bytes())
}

func generateToken() (string, error) { // email/reset tokens
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func buildVerificationEmail(username, verificationURL string) (string, error) {
	tmpl, err := template.ParseFiles("templates/Email_Templates/verifyEmail.html")
	if err != nil {
		return "", err
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, struct {
		Username        string
		VerificationURL string
	}{
		Username:        username,
		VerificationURL: verificationURL,
	}); err != nil {
		return "", err
	}

	return buf.String(), nil
}

func buildPasswordResetEmail(resetURL string) (string, error) {
	tmpl, err := template.ParseFiles("templates/Email_Templates/resetEmail.html")
	if err != nil {
		return "", err
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, struct {
		ResetURL string
	}{
		ResetURL: resetURL,
	}); err != nil {
		return "", err
	}

	return buf.String(), nil
}

func normalizeEmail(email string) string {
	return strings.ToLower(strings.TrimSpace(email))
}

// Old email link function just returns text and url
// func emailLink(url, text string) string {
// 	return text + " " + url
// }

func (a *App) handleShoppingList(w http.ResponseWriter, r *http.Request) {
	userID, ok := a.getUserIDFromSession(r)
	if !ok {
		http.Redirect(w, r, "/users/v1/login", http.StatusSeeOther)
		return
	}

	username, err := a.Users.GetUsernameByID(userID)
	if err != nil {
		log.Printf("Error getting username for user ID %d: %v", userID, err)
		http.Error(w, "could not load user info", http.StatusInternalServerError)
		return
	}

	needOnly := r.URL.Query().Get("need_only") == "1"

	items, err := a.Shopping.GetItems(userID)
	if err != nil {
		log.Printf("Error getting shopping list for user ID %d: %v", userID, err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	recipes, err := a.Shopping.GetRecipes(userID)
	if err != nil {
		log.Printf("Error getting shopping list recipes for user ID %d: %v", userID, err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	data := shoppingListData(items, recipes, needOnly)
	data["Username"] = username
	err = tpl.ExecuteTemplate(w, "shoppingList.html", data)
	if err != nil {
		log.Printf("Error rendering shopping list template: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
}

func (a *App) handleShoppingListAdd(w http.ResponseWriter, r *http.Request) {
	userID, ok := a.getUserIDFromSession(r)
	if !ok {
		w.Header().Set("HX-Redirect", "/users/v1/login")
		return
	}

	if err := r.ParseForm(); err != nil {
		http.Error(w, "could not parse form", http.StatusBadRequest)
		return
	}

	recipeID, err := strconv.ParseInt(r.FormValue("recipe_id"), 10, 64)
	if err != nil {
		http.Error(w, "invalid recipe id", http.StatusBadRequest)
		return
	}

	versionID, err := a.Recipes.GetLatestVersionID(recipeID)
	if err != nil {
		http.Error(w, "recipe not found", http.StatusNotFound)
		return
	}

	ingredients, err := a.Recipes.GetIngredients(versionID)
	if err != nil {
		log.Printf("Error loading ingredients for recipe %d: %v", recipeID, err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	if err := a.Shopping.AddRecipeIngredients(userID, versionID, ingredients); err != nil {
		log.Printf("Error adding recipe %d to shopping list for user ID %d: %v", recipeID, userID, err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// Swap the button for a version of itself that confirms the add.
	if err := tpl.ExecuteTemplate(w, "shopping-btn", map[string]any{
		"RecipeID": recipeID,
		"Added":    true,
	}); err != nil {
		log.Printf("Error rendering shopping button: %v", err)
	}
}

func (a *App) handleShoppingListRemove(w http.ResponseWriter, r *http.Request) {
	userID, ok := a.getUserIDFromSession(r)
	if !ok {
		w.Header().Set("HX-Redirect", "/users/v1/login")
		return
	}

	if err := a.Shopping.RemoveItem(userID, r.URL.Query().Get("name"), r.URL.Query().Get("unit")); err != nil {
		log.Printf("Error removing shopping list item for user ID %d: %v", userID, err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	a.renderShoppingListSection(w, userID, needOnlyFrom(r))
}

// handleShoppingListRemoveRecipe takes a whole recipe back off the list, along
// with every ingredient it put there.
func (a *App) handleShoppingListRemoveRecipe(w http.ResponseWriter, r *http.Request) {
	userID, ok := a.getUserIDFromSession(r)
	if !ok {
		w.Header().Set("HX-Redirect", "/users/v1/login")
		return
	}

	recipeID, err := strconv.ParseInt(r.URL.Query().Get("recipe_id"), 10, 64)
	if err != nil {
		http.Error(w, "invalid recipe id", http.StatusBadRequest)
		return
	}

	if err := a.Shopping.RemoveRecipe(userID, recipeID); err != nil {
		log.Printf("Error removing recipe %d from shopping list for user ID %d: %v", recipeID, userID, err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// The recipe page toggles a single button, the shopping list page redraws the
	// whole section it just deleted a recipe from.
	if r.URL.Query().Get("render") == "button" {
		if err := tpl.ExecuteTemplate(w, "shopping-btn", map[string]any{
			"RecipeID": recipeID,
			"Added":    false,
		}); err != nil {
			log.Printf("Error rendering shopping button: %v", err)
		}
		return
	}

	a.renderShoppingListSection(w, userID, needOnlyFrom(r))
}

func (a *App) handleShoppingListCheck(w http.ResponseWriter, r *http.Request) {
	userID, ok := a.getUserIDFromSession(r)
	if !ok {
		w.Header().Set("HX-Redirect", "/users/v1/login")
		return
	}

	if err := r.ParseForm(); err != nil {
		http.Error(w, "could not parse form", http.StatusBadRequest)
		return
	}

	name := r.URL.Query().Get("name")
	unit := r.URL.Query().Get("unit")
	checked := r.FormValue("checked") != ""

	if err := a.Shopping.SetChecked(userID, name, unit, checked); err != nil {
		log.Printf("Error checking shopping list item for user ID %d: %v", userID, err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	a.renderShoppingListSection(w, userID, needOnlyFrom(r))
}

// handleShoppingListCheckAll ticks off, or clears, every line at once.
func (a *App) handleShoppingListCheckAll(w http.ResponseWriter, r *http.Request) {
	userID, ok := a.getUserIDFromSession(r)
	if !ok {
		w.Header().Set("HX-Redirect", "/users/v1/login")
		return
	}

	if err := r.ParseForm(); err != nil {
		http.Error(w, "could not parse form", http.StatusBadRequest)
		return
	}

	if err := a.Shopping.SetAllChecked(userID, r.FormValue("checked") != ""); err != nil {
		log.Printf("Error checking all shopping list items for user ID %d: %v", userID, err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	a.renderShoppingListSection(w, userID, needOnlyFrom(r))
}

// handleShoppingListQty nudges how much of a line to actually buy, for when the shopper wants a different amount than the recipes worked out.
func (a *App) handleShoppingListQty(w http.ResponseWriter, r *http.Request) {
	userID, ok := a.getUserIDFromSession(r)
	if !ok {
		w.Header().Set("HX-Redirect", "/users/v1/login")
		return
	}

	delta, err := strconv.ParseFloat(r.URL.Query().Get("delta"), 64)
	if err != nil {
		http.Error(w, "invalid delta", http.StatusBadRequest)
		return
	}

	name := r.URL.Query().Get("name")
	unit := r.URL.Query().Get("unit")

	if err := a.Shopping.AdjustQuantity(userID, name, unit, delta); err != nil {
		log.Printf("Error adjusting shopping list quantity for user ID %d: %v", userID, err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	a.renderShoppingListSection(w, userID, needOnlyFrom(r))
}

func (a *App) handleShoppingListToPantry(w http.ResponseWriter, r *http.Request) {
	userID, ok := a.getUserIDFromSession(r)
	if !ok {
		w.Header().Set("HX-Redirect", "/users/v1/login")
		return
	}

	if _, err := a.Shopping.AddCheckedToPantry(userID, a.Pantry); err != nil {
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	a.renderShoppingListSection(w, userID, needOnlyFrom(r))
}

// handleShoppingListFilter: redraws the list with or without the lines the pantry already covers.
func (a *App) handleShoppingListFilter(w http.ResponseWriter, r *http.Request) {
	userID, ok := a.getUserIDFromSession(r)
	if !ok {
		w.Header().Set("HX-Redirect", "/users/v1/login")
		return
	}

	if err := r.ParseForm(); err != nil {
		http.Error(w, "could not parse form", http.StatusBadRequest)
		return
	}

	a.renderShoppingListSection(w, userID, r.FormValue("need_only") != "")
}

func needOnlyFrom(r *http.Request) bool {
	return r.URL.Query().Get("need_only") == "1"
}

// only what I need to buy filter
func shoppingListRows(items []services.ShoppingListItem, needOnly bool) []services.ShoppingListItem {
	if !needOnly {
		return items
	}
	var kept []services.ShoppingListItem
	for _, item := range items {
		if item.NeedsBuying() {
			kept = append(kept, item)
		}
	}
	return kept
}

func shoppingListData(items []services.ShoppingListItem, recipes []services.ShoppingListRecipe, needOnly bool) map[string]any {
	shown := shoppingListRows(items, needOnly)

	allChecked := len(items) > 0
	anyChecked := false
	remaining := 0
	for _, item := range items {
		if !item.Checked {
			allChecked = false
			remaining++
			continue
		}
		anyChecked = true
	}

	return map[string]any{
		"Items":      shown,
		"Recipes":    recipes,
		"NeedOnly":   needOnly,
		"AllChecked": allChecked,
		"AnyChecked": anyChecked,
		"Total":      len(items),
		"Remaining":  remaining,
		"Hidden":     len(items) - len(shown),
	}
}

func (a *App) renderShoppingListSection(w http.ResponseWriter, userID int, needOnly bool) {
	items, err := a.Shopping.GetItems(userID)
	if err != nil {
		log.Printf("Error getting shopping list for user ID %d: %v", userID, err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	recipes, err := a.Shopping.GetRecipes(userID)
	if err != nil {
		log.Printf("Error getting shopping list recipes for user ID %d: %v", userID, err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	if err := tpl.ExecuteTemplate(w, "shopping-list-section", shoppingListData(items, recipes, needOnly)); err != nil {
		log.Printf("Error rendering shopping list section: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
}

func (a *App) handlePantry(w http.ResponseWriter, r *http.Request) {
	userID, ok := a.getUserIDFromSession(r)
	if !ok {
		http.Redirect(w, r, "/users/v1/login", http.StatusSeeOther)
		return
	}

	username, err := a.Users.GetUsernameByID(userID)
	if err != nil {
		log.Printf("Error getting username for user ID %d: %v", userID, err)
		http.Error(w, "could not load user info", http.StatusInternalServerError)
		return
	}

	items, err := a.Pantry.GetPantryItems(userID)
	if err != nil {
		log.Printf("Error getting pantry items for user ID %d: %v", userID, err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	err = tpl.ExecuteTemplate(w, "pantry.html", map[string]any{
		"Username": username,
		"Items":    items,
	})
	if err != nil {
		log.Printf("Error rendering pantry template: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
}

func (a *App) handlePantryAdd(w http.ResponseWriter, r *http.Request) {
	userID, ok := a.getUserIDFromSession(r)
	if !ok {
		http.Redirect(w, r, "/users/v1/login", http.StatusSeeOther)
		return
	}

	if err := r.ParseForm(); err != nil {
		http.Error(w, "could not parse form", http.StatusBadRequest)
		return
	}

	name := r.FormValue("name")
	if name != "" {
		if err := a.Pantry.AddPantryItem(userID, name, r.FormValue("quantity"), r.FormValue("unit")); err != nil {
			if errors.Is(err, services.ErrInvalidQuantity) {
				a.renderPantrySection(w, userID, "Enter a quantity like 2, 1/2 or 1 1/2.")
				return
			}
			log.Printf("Error adding pantry item for user ID %d: %v", userID, err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}
	}

	a.renderPantrySection(w, userID, "")
}

func (a *App) handlePantryRemove(w http.ResponseWriter, r *http.Request) {
	userID, ok := a.getUserIDFromSession(r)
	if !ok {
		http.Redirect(w, r, "/users/v1/login", http.StatusSeeOther)
		return
	}

	if err := a.Pantry.RemovePantryItem(userID, r.URL.Query().Get("name"), r.URL.Query().Get("unit")); err != nil {
		log.Printf("Error removing pantry item for user ID %d: %v", userID, err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	a.renderPantrySection(w, userID, "")
}

func (a *App) renderPantrySection(w http.ResponseWriter, userID int, errMsg string) {
	items, err := a.Pantry.GetPantryItems(userID)
	if err != nil {
		log.Printf("Error getting pantry items for user ID %d: %v", userID, err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	if err := tpl.ExecuteTemplate(w, "pantry-section", map[string]any{
		"Items": items,
		"Error": errMsg,
	}); err != nil {
		log.Printf("Error rendering pantry section: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
}
