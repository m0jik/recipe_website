package services

import "database/sql"

var version string = "V1"

func GetTagString(s *RecipeServiceV1, tagString, primaryName, variantName, creatorID string) *sql.Row {
	return s.DB.QueryRow(
		//TODO: Fix this database call and put it into its own service to interface into
		`
		SELECT COALESCE(GROUP_CONCAT(t.name, ','), '')
		FROM tags`+version+` t
		JOIN recipeTags`+version+` rt ON rt.tag_id = t.id
		WHERE rt.recipe_id = ?
		`,
		primaryName, variantName, creatorID,
	)
}

func InsertRecipeIntoRecipesTable(s *RecipeServiceV1, userID, title, imageURL, primaryName, variantName, creatorID, description string, servings, prepTimeMinutes int) (sql.Result, error) {
	return s.DB.Exec(
		`
		INSERT INTO recipes`+version+`
		(user_id, title, image_url, description, servings, prep_time_minutes)
		VALUES (?, ?, ?, ?, ?, ?)
		`,
		userID,
		title,
		imageURL,
		description,
		servings,
		prepTimeMinutes,
	)
}

func InsertRecipeIntoRecipeVersionsTable(s *RecipeServiceV1, primaryName, variantName, creatorID string) (sql.Result, error) {
	return s.DB.Exec( // creates the first version
		`
		INSERT INTO recipe_versions`+version+` (recipe_id, version_number)
        VALUES (?, 1)
		`,
		primaryName, variantName, creatorID, //TODO: Needs fix
	)
}

func InsertTagsIntoTagsTable(tx sqlExecutor, tag string) (sql.Result, error) {
	return tx.Exec(
		`
		INSERT INTO tags`+version+`(name) VALUES (?) ON CONFLICT(name) DO NOTHING
		`,
		tag,
	)
}

func InsertRecipeIntoRecipeTagsTable(tx sqlExecutor, primaryName, variantName, creatorID string, tagID int64) (sql.Result, error) {
	return tx.Exec(
		`
		INSERT OR IGNORE INTO recipeTags`+version+`(recipe_id, tag_id) VALUES
		(?, ?)
		`,
		primaryName, variantName, creatorID, tagID,
	)
}

func InsertIntoIngredientsTable(s *RecipeServiceV1, versionID int64, name, qty, unit string) (sql.Result, error) {
	return s.DB.Exec(
		`
		INSERT INTO ingredients`+version+` (recipe_version_id, name, quantity, unit)
		VALUES (?, ?, ?, ?)
		`,
		versionID, name, qty, unit,
	)
}

func InsertIntoInstructionsTable(s *RecipeServiceV1, versionID int64, i int, instruction, note string) (sql.Result, error) {
	return s.DB.Exec(
		`
		INSERT INTO instructions`+version+` (recipe_version_id, step_number, instruction, notes)
		VALUES (?, ?, ?, ?)
		`,
		versionID, i+1, instruction, note,
	)
}

func InsertIntoStepIngredientsTable(s *RecipeServiceV1, versionID int64, i int, step_ingredient string) (sql.Result, error) {
	return s.DB.Exec(
		`
		INSERT INTO step_ingredients`+version+` (recipe_id, step_id, step_ingredient)
		VALUES (?, ?, ?)
		`,
		versionID, i+1, step_ingredient,
	)
}

func GetLargestVersionNumber(tx sqlExecutor, primaryName, variantName, creatorID string) *sql.Row {
	return tx.QueryRow(
		`
		SELECT COALESCE(MAX(version_number), 0)
		FROM recipe_versions`+version+`
		WHERE recipe_id = ?
		`,
		primaryName, variantName, creatorID,
	)
}

func InsertNewRecipeVersionIntoRecipeVersionTable(tx sqlExecutor, primaryName, variantName, creatorID string, maxVersion int) (sql.Result, error) {
	return tx.Exec(
		`
		INSERT INTO recipe_versions`+version+` (recipe_id, version_number)
		VALUES (?, ?)
		`,
		primaryName, variantName, creatorID, maxVersion+1,
	)
}

func GetIngredientsFromIngredientsTable(q sqlExecutor, recipeVersionID int64) (*sql.Rows, error) {
	return q.Query(
		`
		SELECT id, recipe_version_id, name, quantity, unit
		FROM ingredients`+version+`
		WHERE recipe_version_id = ?
		ORDER BY id
		`,
		recipeVersionID,
	)
}

func GetStepsFromInstructionsTable(tx sqlExecutor, recipeVersionID int64) (*sql.Rows, error) {
	return tx.Query(
		`
		SELECT id, recipe_version_id, step_number, instruction, COALESCE(notes, '') 
		FROM instructions`+version+` WHERE recipe_version_id = ? 
		ORDER BY step_number
		`,
		recipeVersionID,
	)
}

func GetVersionsFromRecipeVersionsTable(s *RecipeServiceV1, primaryName, variantName, creatorID string) (*sql.Rows, error) {
	return s.DB.Query(
		`
		SELECT id, version_number, created_at FROM recipe_versions`+version+`
		WHERE recipe_id = ?
		ORDER BY version_number DESC
		`,
		primaryName, variantName, creatorID,
	)
}

func GetVersionBelongingToUserID(s *RecipeServiceV1, versionID int64, primaryName, variantName, creatorID, userID string) *sql.Row {
	return s.DB.QueryRow(
		`
		SELECT rv.id, rv.version_number, rv.created_at
		FROM recipe_versions`+version+` rv
		JOIN recipes`+version+` r ON r.id = rv.recipe_id
		WHERE rv.id = ? AND rv.recipe_id = ? AND r.user_id = ?
		`,
		versionID, primaryName, variantName, creatorID, userID,
	)
}

func GetStepIngredientsFromStepIngredientsTable(s *RecipeServiceV1, recipeVersionID int64) (*sql.Rows, error) {
	return s.DB.Query(
		`
		SELECT id, recipe_id, step_id, step_ingredient
		FROM step_ingredients`+version+`
		WHERE recipe_id = ?
		`,
		recipeVersionID,
	)
}

func GetRecipesByUserID(s *RecipeServiceV1, userID string) (*sql.Rows, error) {
	return s.DB.Query(
		// `SELECT r.id, r.title, COALESCE(rv.id, 0)
		//  FROM recipesV1 r
		//  LEFT JOIN recipe_versionsV1 rv ON rv.recipe_id = r.id
		//    AND rv.version_number = (SELECT MAX(version_number) FROM recipe_versionsV1 WHERE recipe_id = r.id)
		//  WHERE r.user_id = ?
		//  ORDER BY r.created_at DESC`,
		`
		SELECT
            r.id,
            r.title,
			r.user_id,
            0 AS version_id,
            COALESCE(r.description, '') AS description,
            COALESCE(r.image_url, '') AS image_url,
			COALESCE(
				(SELECT GROUP_CONCAT(t.name, ',')
				FROM tags`+version+` t
				JOIN recipeTags`+version+` rt ON rt.tag_id = t.id
				WHERE rt.recipe_id = r.id),
				''
			)
        FROM recipes`+version+` r
     	WHERE r.user_id = ?
    	ORDER BY r.created_at DESC
		`,
		userID,
	)
}

func GetLatestVersionIDFromRecipeVersionsTable(tx sqlExecutor, primaryName, variantName, creatorID string) *sql.Row {
	return tx.QueryRow( //TODO: More database fixes
		`
        SELECT id
        FROM recipe_versionsV1
        WHERE recipe_id = ?
        ORDER BY version_number DESC
        LIMIT 1
    	`,
		primaryName, variantName, creatorID,
	)
}

func GetUserFromRecipesTable(s *RecipeServiceV1, recipeID int64) *sql.Row {
	return s.DB.QueryRow(
		`
		SELECT user_id FROM recipes`+version+` WHERE id = ?
		`,
		recipeID,
	)
}

func SearchByTag(conditions []string) []string {
	return append(conditions,
		`
		EXISTS (
			SELECT 1
			FROM tags`+version+` t JOIN recipeTags`+version+` rt ON rt.tag_id = t.id
			WHERE rt.recipe_id = r.id AND t.name = ?
		)
		`,
	)
}

func SearchByTitleAndDescription(conditions []string) []string {
	return append(conditions,
		`
		(r.title LIKE ? OR r.description LIKE ? OR EXISTS (
			SELECT 1
			FROM tagsV1 t JOIN recipeTagsV1 rt ON rt.tag_id = t.id
			WHERE rt.recipe_id = r.id AND t.name LIKE ?
		) OR EXISTS (
			SELECT 1
			FROM ingredientsV1 i
			JOIN recipe_versionsV1 rv ON rv.id = i.recipe_version_id
			WHERE rv.recipe_id = r.id
		  	AND rv.version_number = (
				SELECT MAX(version_number)
				FROM recipe_versionsV1
				WHERE recipe_id = r.id
			)
		  	AND i.name LIKE ?
		))
		`,
	)
}
