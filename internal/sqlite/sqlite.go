package sqlite

import (
	"github.com/jmoiron/sqlx"
	_ "github.com/mattn/go-sqlite3"
)

func New(path string) (*sqlx.DB, error) {
	db, err := sqlx.Open("sqlite3", path)
	if err != nil {
		return nil, err
	}
	return db, nil
}

func Migrate(db *sqlx.DB) error {
	schema := `
	CREATE TABLE IF NOT EXISTS usersV1 (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		username TEXT NOT NULL UNIQUE,
		password_hash TEXT NOT NULL,
		email TEXT NOT NULL UNIQUE,
		is_verified BOOLEAN NOT NULL DEFAULT FALSE,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);
	
	CREATE TABLE IF NOT EXISTS sessionsV1 (
		id TEXT PRIMARY KEY,
		user_id INTEGER NOT NULL,
		expires_at DATETIME NOT NULL,
		FOREIGN KEY(user_id) REFERENCES usersV1(id)
	);

	CREATE TABLE IF NOT EXISTS recipesV1 (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		user_id INTEGER NOT NULL,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		title TEXT NOT NULL,
		image_url TEXT,
		description TEXT,
		FOREIGN KEY (user_id) REFERENCES usersV1(id)
	);

	CREATE TABLE IF NOT EXISTS recipe_versionsV1(
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		recipe_id INTEGER NOT NULL,
		version_number INTEGER NOT NULL,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		UNIQUE(recipe_id, version_number),
		FOREIGN KEY (recipe_id) REFERENCES recipesV1(id)
	);

	CREATE TABLE IF NOT EXISTS ingredientsV1 (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		recipe_version_id INTEGER NOT NULL,
		name TEXT NOT NULL, 
		quantity REAL NOT NULL, 
		unit TEXT NOT NULL,
		FOREIGN KEY(recipe_version_id) REFERENCES recipe_versionsV1(id)
	);

	CREATE TABLE IF NOT EXISTS instructionsV1 (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		recipe_version_id INTEGER NOT NULL,
		step_number INTEGER NOT NULL,
		instruction TEXT NOT NULL,
		notes TEXT,
		UNIQUE(recipe_version_id, step_number),
		FOREIGN KEY (recipe_version_id) REFERENCES recipe_versionsV1(id)
	);

	CREATE TABLE IF NOT EXISTS passResetV1 (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		user_id INTERGER NOT NULL,
		token TEXT NOT NULL,
		expires_at DATETIME NOT NULL,
		FOREIGN KEY (user_id) REFERENCES usersV1(id)
	);

	CREATE TABLE IF NOT EXISTS emailVerifyV1 (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		user_id INTERGER NOT NULL,
		token TEXT NOT NULL,
		expires_at DATETIME NOT NULL,
		FOREIGN KEY (user_id) REFERENCES usersV1(id)
	);
	`
	_, err := db.Exec(schema)
	return err
}
