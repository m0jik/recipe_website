// Package sqlite provides functions to interact with the SQLite database, including connection management and schema migration.
package sqlite

import (
	"fmt"

	"github.com/jmoiron/sqlx"
	_ "modernc.org/sqlite"
)

type RecipeServiceV1 struct {
	DB *sqlx.DB
}

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
		username TEXT NOT NULL UNIQUE,
		password_hash TEXT NOT NULL,
		email TEXT NOT NULL UNIQUE,
		is_verified BOOLEAN NOT NULL DEFAULT FALSE,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);
	
	CREATE TABLE IF NOT EXISTS sessionsV1 (
		id TEXT PRIMARY KEY,
		user_id TEXT NOT NULL,
		expires_at DATETIME NOT NULL,
		FOREIGN KEY(user_id) REFERENCES usersV1(username)
	);

	CREATE TABLE IF NOT EXISTS recipesV1 (
		primary_name TEXT NOT NULL,
		variant_name TEXT NOT NULL,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		description TEXT,
		image_url TEXT,
		creator_id TEXT NOT NULL,
		servings INTEGER,
		prep_time_minutes TEXT,
		PRIMARY KEY (primary_name, variant_name, creator_id),
		FOREIGN KEY (creator_id) REFERENCES usersV1(username)
	);

	CREATE TABLE IF NOT EXISTS tagsV1 (
		name TEXT NOT NULL UNIQUE
	);

	CREATE TABLE IF NOT EXISTS recipeTagsV1 (
		recipe_primary_name TEXT NOT NULL,
		recipe_variant_name TEXT NOT NULL,
		recipe_creator_id TEXT NOT NULL,
		recipe_tag_name TEXT NOT NULL UNIQUE,
		PRIMARY KEY (recipe_primary_name, recipe_variant_name, recipe_creator_id, recipe_tag_name),
		FOREIGN KEY (recipe_primary_name, recipe_variant_name, recipe_creator_id) REFERENCES recipesV1(primary_name, variant_name, creator_id),
		FOREIGN KEY (recipe_tag_name) REFERENCES tagsV1(name)
	);

	CREATE INDEX IF NOT EXISTS idx_recipeTagsV1_tag_id ON recipeTagsV1(recipe_primary_name, recipe_variant_name, recipe_creator_id, recipe_tag_name);

	CREATE TABLE IF NOT EXISTS recipe_versionsV1(
		recipe_primary_name TEXT NOT NULL,
		recipe_variant_name TEXT NOT NULL,
		recipe_creator_id TEXT NOT NULL,
		version_number INTEGER NOT NULL,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		UNIQUE(recipe_primary_name, recipe_variant_name, recipe_creator_id, version_number)
		FOREIGN KEY (recipe_primary_name, recipe_variant_name, recipe_creator_id) REFERENCES recipesV1(primary_name, variant_name, creator_id)
	);

	CREATE TABLE IF NOT EXISTS ingredientsV1 (
		recipe_primary_name TEXT NOT NULL,
		recipe_variant_name TEXT NOT NULL,
		recipe_creator_id TEXT NOT NULL,
		name TEXT NOT NULL,
		quantity TEXT NOT NULL, 
		unit TEXT NOT NULL,
		recipe_version_number INTEGER NOT NULL,
		FOREIGN KEY (recipe_primary_name, recipe_variant_name, recipe_creator_id) REFERENCES recipesV1(primary_name, variant_name, creator_id)
		FOREIGN KEY (recipe_version_number) REFERENCES recipe_versionsV1(version_number)
	);

	CREATE TABLE IF NOT EXISTS instructionsV1 (
		step_number INTEGER NOT NULL,
		instruction TEXT NOT NULL,
		recipe_primary_name TEXT NOT NULL,
		recipe_variant_name TEXT NOT NULL,
		recipe_creator_id TEXT NOT NULL,
		recipe_version_number INTEGER NOT NULL,
		FOREIGN KEY (recipe_primary_name, recipe_variant_name, recipe_creator_id) REFERENCES recipesV1(primary_name, variant_name, creator_id)
		FOREIGN KEY (recipe_version_number) REFERENCES recipe_versionsV1(version_number)
	);

	CREATE TABLE IF NOT EXISTS passResetV1 (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		user_id TEXT NOT NULL,
		token TEXT NOT NULL,
		expires_at DATETIME NOT NULL,
		FOREIGN KEY (user_id) REFERENCES usersV1(username)
	);

	CREATE TABLE IF NOT EXISTS emailVerifyV1 (
		user_id TEXT PRIMARY KEY NOT NULL,
		token TEXT NOT NULL,
		expires_at DATETIME NOT NULL,
		FOREIGN KEY (user_id) REFERENCES usersV1(username)
	);
	
	CREATE TABLE IF NOT EXISTS userPantryV1 (
		user_id TEXT NOT NULL,
		name TEXT NOT NULL,
		quantity TEXT NOT NULL,
		unit TEXT NOT NULL DEFAULT '',
		PRIMARY KEY (user_id, name, unit),
		FOREIGN KEY (user_id) REFERENCES usersV1(username)
	);

	CREATE TABLE IF NOT EXISTS userShoppingListV2 (
		user_id TEXT NOT NULL,
		name TEXT NOT NULL,
		quantity TEXT NOT NULL,
		unit TEXT NOT NULL DEFAULT '',
		source_recipe_primary_name TEXT NOT NULL,
		source_recipe_variant_name TEXT NOT NULL,
		source_recipe_creator_id TEXT NOT NULL,
		UNIQUE (user_id, name, unit, source_recipe_primary_name, source_recipe_variant_name, source_recipe_creator_id),
		FOREIGN KEY (user_id) REFERENCES usersV1(username),
		FOREIGN KEY (source_recipe_primary_name, source_recipe_variant_name, source_recipe_creator_id) REFERENCES recipe_versionsV1(recipe_primary_name, recipe_variant_name, recipe_creator_id)
	);
		
	CREATE TABLE IF NOT EXISTS userShoppingStateV1 (
		user_id TEXT NOT NULL,
		name TEXT NOT NULL,
		unit TEXT NOT NULL DEFAULT '',
		checked BOOLEAN NOT NULL DEFAULT FALSE,
		bought_qty TEXT NOT NULL DEFAULT '',
		bought_unit TEXT NOT NULL DEFAULT '',
		PRIMARY KEY (user_id, name, unit),
		FOREIGN KEY (user_id) REFERENCES usersV1(username)
	);

	CREATE TABLE IF NOT EXISTS step_ingredientsV1 (
	    name TEXT NOT NULL,
		amount TEXT NOT NULL,
		unit TEXT NOT NULL,
		step_number INTEGER NOT NULL,
		recipe_primary_name TEXT NOT NULL,
		recipe_variant_name TEXT NOT NULL,
		recipe_creator_id TEXT NOT NULL,
		FOREIGN KEY (step_number, recipe_primary_name, recipe_variant_name, recipe_creator_id) REFERENCES instructionsV1(step_number, recipe_primary_name, recipe_variant_name, recipe_creator_id)
	);

	CREATE TABLE IF NOT EXISTS cookBookV1 (
		user_id TEXT NOT NULL,
		recipe_primary_name TEXT NOT NULL,
		recipe_variant_name TEXT NOT NULL,
		recipe_creator_id TEXT NOT NULL,
		FOREIGN KEY (user_id) REFERENCES usersV1(username),
		FOREIGN KEY (recipe_primary_name, recipe_variant_name, recipe_creator_id) REFERENCES recipesV1(primary_name, variant_name, creator_id)
		UNIQUE (user_id, recipe_primary_name, recipe_variant_name, recipe_creator_id)
	);
	`
	_, err := db.Exec(schema)
	return err
}
