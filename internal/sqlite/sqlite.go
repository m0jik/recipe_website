// Package sqlite provides functions to interact with the SQLite database, including connection management and schema migration.
package sqlite

import (
	"fmt"

	"github.com/jmoiron/sqlx"
	_ "modernc.org/sqlite"
)

func New(path string) (*sqlx.DB, error) {
	db, err := sqlx.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("failed to open sqlite db: %w", err)
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
		servings INTEGER,
		prep_time_minutes INTEGER,
		FOREIGN KEY (user_id) REFERENCES usersV1(id)
	);

	CREATE TABLE IF NOT EXISTS tagsV1 (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		name TEXT NOT NULL UNIQUE
	);

	CREATE TABLE IF NOT EXISTS recipeTagsV1 (
		recipe_id INTEGER NOT NULL,
		tag_id INTEGER NOT NULL,
		PRIMARY KEY (recipe_id, tag_id),
		FOREIGN KEY (recipe_id) REFERENCES recipesV1(id),
		FOREIGN KEY (tag_id) REFERENCES tagsV1(id)
	);

	CREATE INDEX IF NOT EXISTS idx_recipeTagsV1_tag_id ON recipeTagsV1(tag_id);

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
		quantity TEXT NOT NULL, 
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
		user_id INTEGER NOT NULL,
		token TEXT NOT NULL,
		expires_at DATETIME NOT NULL,
		FOREIGN KEY (user_id) REFERENCES usersV1(id)
	);

	CREATE TABLE IF NOT EXISTS emailVerifyV1 (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		user_id INTEGER NOT NULL,
		token TEXT NOT NULL,
		expires_at DATETIME NOT NULL,
		FOREIGN KEY (user_id) REFERENCES usersV1(id)
	);
	
	CREATE TABLE IF NOT EXISTS userPantryV1 (
		user_id INTEGER NOT NULL,
		name TEXT NOT NULL,
		quantity TEXT NOT NULL,
		unit TEXT NOT NULL DEFAULT '',
		PRIMARY KEY (user_id, name, unit),
		FOREIGN KEY (user_id) REFERENCES usersV1(id)
	);

	CREATE TABLE IF NOT EXISTS userShoppingListV2 (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		user_id INTEGER NOT NULL,
		name TEXT NOT NULL,
		quantity TEXT NOT NULL,
		unit TEXT NOT NULL DEFAULT '',
		source_recipe_version_id INTEGER,
		UNIQUE (user_id, name, unit, source_recipe_version_id),
		FOREIGN KEY (user_id) REFERENCES usersV1(id),
		FOREIGN KEY (source_recipe_version_id) REFERENCES recipe_versionsV1(id)
	);
		
	-- What the shopper did to a line, as opposed to what the recipes asked for:
	CREATE TABLE IF NOT EXISTS userShoppingStateV1 (
		user_id INTEGER NOT NULL,
		name TEXT NOT NULL,
		unit TEXT NOT NULL DEFAULT '',
		checked BOOLEAN NOT NULL DEFAULT FALSE,
		qty_override TEXT NOT NULL DEFAULT '',
		PRIMARY KEY (user_id, name, unit),
		FOREIGN KEY (user_id) REFERENCES usersV1(id)
	);
	`
	_, err := db.Exec(schema)
	return err
}
