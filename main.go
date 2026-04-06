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

var tpl = template.Must(template.ParseGlob("templates/*.html"))

const cookieName = "session_id"

type App struct {
	DB      *sqlx.DB
	Cfg     *config.Config
	Users   *services.UserService
	Recipes *services.RecipeService
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
	defer db.Close()

	log.Println("Running migrations...")
	if err := sqlite.Migrate(db); err != nil {
		log.Printf("db init error: %v", err)
		return
	}
	log.Println("Migrations complete.")

	app := &App{
		DB:      db,
		Cfg:     cfg,
		Users:   services.NewUserService(db),
		Recipes: services.NewRecipeService(db),
	}

	log.Println("Setting up handlers...")
	mux := http.NewServeMux()
	mux.HandleFunc("/v1", app.handleIndex) // Implement versioning
	mux.HandleFunc("/users/v1/register", app.handleRegister)
	mux.HandleFunc("/users/v1/login", app.handleLogin)
	mux.HandleFunc("/users/v1/logout", app.handleLogout)
	mux.HandleFunc("/users/v1/request_reset", app.handleRequestReset)
	mux.HandleFunc("/users/v1/reset", app.handleReset)
	mux.HandleFunc("/recipes/v1/new", app.createNewRecipe)
	mux.HandleFunc("/recipes/v1/edit", app.handleEditRecipe)
	mux.HandleFunc("/recipes/v1/addIngredient", app.handleAddIngredient)
	mux.HandleFunc("/recipes/v1/addStep", app.handleAddStepAndNote)
	mux.HandleFunc("/recipes/v1/delete-ingredient", app.handleDeleteIngredient)
	mux.HandleFunc("/recipes/v1/delete-instruction", app.handleDeleteInstruction)
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
	tpl.ExecuteTemplate(w, "index.html", map[string]any{
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
		// _, err = a.DB.Exec("INSERT INTO usersV1(username, password_hash) VALUES (?, ?)", username, string(hash))
		if err := a.Users.CreateUser(username, hash); err != nil {
			http.Error(w, "could not create user", http.StatusInternalServerError)
			return
		}
		http.Redirect(w, r, "/users/v1/login", http.StatusSeeOther)
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
		//row := a.DB.QueryRow("SELECT id, password_hash FROM usersV1 WHERE username = ?", username)

		id, hash, err := a.Users.GetUserCredentials(username)
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
		//a.DB.Exec("DELETE FROM sessionsV1 WHERE id = ?", c.Value)

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
		tpl.ExecuteTemplate(w, "request_reset.html", nil)
		return
	case http.MethodPost:
		if err := r.ParseForm(); err != nil {
			http.Error(w, "invalid form", http.StatusBadRequest)
			return
		}
		username := r.FormValue("username")
		// var id int
		// row := a.DB.QueryRow("SELECT id FROM usersV1 WHERE username = ?", username)
		// if err := row.Scan(&id); err != nil {
		//  	http.Error(w, "user not found", http.StatusNotFound)
		//  	return
		// }
		id, err := a.Users.GetUserIDByUsername(username)
		if err != nil {
			http.Error(w, "user not found", http.StatusNotFound)
			return
		}
		token, err := generateSessionID()
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
		resetLink := "/users/v1/reset?token=" + token
		w.Write([]byte("Reset link: " + resetLink))
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (a *App) handleReset(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		token := r.URL.Query().Get("token")
		tpl.ExecuteTemplate(w, "reset.html", map[string]string{"Token": token})
		return
	case http.MethodPost:
		if err := r.ParseForm(); err != nil {
			http.Error(w, "invalid form", http.StatusBadRequest)
			return
		}
		token := r.FormValue("token")
		newPassword := r.FormValue("password")
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
		//a.DB.Exec("DELETE FROM sessionsV1 WHERE id = ?", c.Value)
		a.Users.DeleteSession(c.Value)
		return 0, false
	}

	if time.Now().After(exp) {
		//a.DB.Exec("DELETE FROM sessionsV1 WHERE id = ?", c.Value)
		a.Users.DeleteSession(c.Value)
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

func (a *App) createNewRecipe(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		a.handleNewRecipeGet(w, r)
	case http.MethodPost:
		a.handleNewRecipePost(w, r)
	}
}

func (a *App) handleNewRecipeGet(w http.ResponseWriter, r *http.Request) {
	idStr := r.URL.Query().Get("id")
	if idStr == "" {
		tpl.ExecuteTemplate(w, "new.html", nil)
		return
	}
	recipeID, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		http.Error(w, "invalid recipe id", http.StatusBadRequest)
		return
	}
	title, imageURL, description, err := a.Recipes.GetRecipeDetails(recipeID)
	if err != nil {
		http.Error(w, "recipe not found", http.StatusNotFound)
		return
	}
	tpl.ExecuteTemplate(w, "new.html", map[string]any{
		"RecipeID":    recipeID,
		"Title":       title,
		"ImageURL":    imageURL,
		"Description": description,
	})
}

func (a *App) handleNewRecipePost(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseMultipartForm(10 << 20); err != nil {
		http.Error(w, "could not parse form", http.StatusBadRequest)
		return
	}

	title := r.FormValue("title")
	description := r.FormValue("description")
	imageURL := r.FormValue("myfile")

	if file, header, err := r.FormFile("image"); err == nil {
		defer file.Close()
		imageURL = "/uploads/" + header.Filename
	}

	if idStr := r.FormValue("recipe_id"); idStr != "" {
		a.handleUpdateRecipe(w, r, idStr, title, imageURL, description)
		return
	}

	a.handleCreateRecipe(w, r, title, imageURL, description)
}

func (a *App) handleUpdateRecipe(w http.ResponseWriter, r *http.Request, idStr, title, imageURL, description string) {
	recipeID, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		http.Error(w, "invalid recipe id", http.StatusBadRequest)
		return
	}
	if err := a.Recipes.UpdateRecipe(recipeID, title, imageURL, description); err != nil {
		http.Error(w, "could not update recipe", http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/recipes/v1/edit?id="+strconv.FormatInt(recipeID, 10), http.StatusSeeOther)
}

func (a *App) handleCreateRecipe(w http.ResponseWriter, r *http.Request, title, imageURL, description string) {
	userID, ok := a.getUserIDFromSession(r)
	if !ok {
		http.Error(w, "not logged in", http.StatusUnauthorized)
		return
	}
	recipeID, err := a.Recipes.CreateRecipe(userID, title, imageURL, description)
	if err != nil {
		http.Error(w, "could not create recipe", http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/recipes/v1/edit?id="+strconv.FormatInt(recipeID, 10), http.StatusSeeOther)
}

func (a *App) handleEditRecipe(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		idStr := r.URL.Query().Get("id")
		id, err := strconv.ParseInt(idStr, 10, 64)
		if err != nil {
			http.Error(w, "invalid recipe id", http.StatusBadRequest)
			return
		}

		data, err := a.Recipes.GetRecipeForEdit(id)
		if err != nil {
			http.Error(w, "recipe not found", http.StatusNotFound)
			return
		}

		tpl.ExecuteTemplate(w, "edit.html", data)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (a *App) handleAddIngredient(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPost:
		if err := r.ParseForm(); err != nil {
			http.Error(w, "invalid form", http.StatusBadRequest)
			return
		}

		recipeVersionID, err := strconv.ParseInt(r.FormValue("recipe_version_id"), 10, 64)
		if err != nil {
			http.Error(w, "invalid version id", http.StatusBadRequest)
			return
		}
		recipeID := r.FormValue("recipe_id")
		quantity, err := strconv.ParseFloat(r.FormValue("quantity"), 64)
		if err != nil {
			quantity = 0
		}
		name := r.FormValue("ingredient")
		unit := r.FormValue("unit")

		if err := a.Recipes.AddIngredient(recipeVersionID, name, quantity, unit); err != nil {
			http.Error(w, "could not add ingredient", http.StatusInternalServerError)
			return
		}

		http.Redirect(w, r, "/recipes/v1/edit?id="+recipeID, http.StatusSeeOther)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (a *App) handleAddStepAndNote(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPost:
		if err := r.ParseForm(); err != nil {
			http.Error(w, "invalid form", http.StatusBadRequest)
			return
		}

		recipeVersionID, err := strconv.ParseInt(r.FormValue("recipe_version_id"), 10, 64)
		if err != nil {
			http.Error(w, "invalid version id", http.StatusBadRequest)
			return
		}
		recipeID := r.FormValue("recipe_id")
		instruction := r.FormValue("step")
		notes := r.FormValue("note")

		if err := a.Recipes.AddInstruction(recipeVersionID, instruction, notes); err != nil {
			http.Error(w, "could not add step", http.StatusInternalServerError)
			return
		}

		http.Redirect(w, r, "/recipes/v1/edit?id="+recipeID, http.StatusSeeOther)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (a *App) handleDeleteIngredient(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPost:
		if err := r.ParseForm(); err != nil {
			http.Error(w, "invalid form", http.StatusBadRequest)
			return
		}

		ingredientId, err := strconv.ParseInt(r.FormValue("ingredient_id"), 10, 64)
		if err != nil {
			http.Error(w, "invalid ingredient id", http.StatusBadRequest)
			return
		}

		recipeVersionId, err := strconv.ParseInt(r.FormValue("recipe_version_id"), 10, 64)
		if err != nil {
			http.Error(w, "invalid recipe version id", http.StatusBadRequest)
			return
		}

		recipeId := r.FormValue("recipe_id") // for redirect

		if err := a.Recipes.DeleteIngredient(recipeVersionId, ingredientId); err != nil {
			http.Error(w, "Could not delete ingredient", http.StatusInternalServerError)
			return
		}

		http.Redirect(w, r, "/recipes/v1/edit?id="+recipeId, http.StatusSeeOther)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (a *App) handleDeleteInstruction(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPost:
		if err := r.ParseForm(); err != nil {
			http.Error(w, "invalid form", http.StatusBadRequest)
			return
		}

		instructionId, err := strconv.ParseInt(r.FormValue("instruction_id"), 10, 64)
		if err != nil {
			http.Error(w, "invalid instruction id", http.StatusBadRequest)
			return
		}

		recipeVersionId, err := strconv.ParseInt(r.FormValue("recipe_version_id"), 10, 64)
		if err != nil {
			http.Error(w, "invalid recipe version id", http.StatusBadRequest)
			return
		}

		recipeId := r.FormValue("recipe_id")

		if err := a.Recipes.DeleteInstruction(recipeVersionId, instructionId); err != nil {
			http.Error(w, "Could not delete instruction", http.StatusInternalServerError)
			return
		}

		if err := a.Recipes.ReorderSteps(recipeVersionId); err != nil {
			http.Error(w, "Could not reorder instructions", http.StatusInternalServerError)
			return
		}

		http.Redirect(w, r, "/recipes/v1/edit?id="+recipeId, http.StatusSeeOther)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}
