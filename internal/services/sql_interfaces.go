package services

import (
	"database/sql"
	"strings"
)

func GetTagString(s *RecipeServiceV1, primaryName, variantName, creatorID string) *sql.Row {
	return s.DB.QueryRow(
		`
		SELECT COALESCE(GROUP_CONCAT(t.name, ','), '')
		FROM tagsV1 t
		JOIN recipeTagsV1 rt ON rt.recipe_tag_name = t.name
		WHERE rt.recipe_primary_name = ?
		AND rt.recipe_variant_name = ?
		AND rt.recipe_creator_id = ?
		`,
		primaryName, variantName, creatorID,
	)
}

func InsertRecipeIntoRecipesTable(s *RecipeServiceV1, imageURL, primaryName, variantName, creatorID, description string, servings, prepTimeMinutes int) (sql.Result, error) {
	return s.DB.Exec(
		`
		INSERT INTO recipesV1 (primary_name, variant_name, description, image_url, creator_id, servings, prep_time_minutes)
		VALUES (?, ?, ?, ?, ?, ?, ?)
	`, primaryName, variantName, description, imageURL, creatorID, servings, prepTimeMinutes)
}

func InsertRecipeIntoRecipeVersionsTable(s *RecipeServiceV1, primaryName, variantName, creatorID string) (sql.Result, error) {
	return s.DB.Exec( // creates the first version
		`
		INSERT INTO recipe_versionsV1 (recipe_primary_name, recipe_variant_name, recipe_creator_id, version_number)
        VALUES (?, ?, ?, 1)
		`,
		primaryName, variantName, creatorID,
	)
}

func InsertTagsIntoTagsTable(tx sqlExecutor, tag string) (sql.Result, error) {
	return tx.Exec(
		`
		INSERT INTO tagsV1(name)
		VALUES (?) 
		ON CONFLICT(name) DO NOTHING
		`,
		tag,
	)
}

func InsertRecipeIntoRecipeTagsTable(tx sqlExecutor, primaryName, variantName, creatorID, tagID string) (sql.Result, error) {
	return tx.Exec(
		`
		INSERT OR IGNORE INTO recipeTagsV1 (recipe_primary_name, recipe_variant_name, recipe_creator_id, recipe_tag_name)
		VALUES (?, ?, ?, ?)
		`,
		primaryName, variantName, creatorID, tagID,
	)
}

func InsertIntoIngredientsTable(s *RecipeServiceV1, versionID int64, name, qty, unit, primaryName, variantName, creatorID string) (sql.Result, error) {
	return s.DB.Exec(
		`
		INSERT INTO ingredientsV1 (recipe_version_number, name, quantity, unit, recipe_primary_name, recipe_variant_name, recipe_creator_id)
		VALUES (?, ?, ?, ?, ?, ?, ?)
		`,
		versionID, name, qty, unit, primaryName, variantName, creatorID,
	)
}

func InsertIntoInstructionsTable(s *RecipeServiceV1, versionID int64, i int, instruction, primaryName, variantName, creatorID string) (sql.Result, error) {
	return s.DB.Exec(
		`
		INSERT INTO instructionsV1 (recipe_primary_name, recipe_variant_name, recipe_creator_id, step_number, instruction, recipe_version_number)
		VALUES (?, ?, ?, ?, ?, ?)
		`,
		primaryName, variantName, creatorID, i+1, instruction, versionID,
	)
}

func InsertIntoStepIngredientsTable(s *RecipeServiceV1, versionID int64, i int, step_ingredient string) (sql.Result, error) {
	return s.DB.Exec(
		`
		INSERT INTO step_ingredientsV1 (recipe_id, step_id, step_ingredient)
		VALUES (?, ?, ?)
		`,
		versionID, i+1, step_ingredient,
	)
}

func GetLargestVersionNumber(tx sqlExecutor, primaryName, variantName, creatorID string) *sql.Row {
	return tx.QueryRow(
		`
		SELECT COALESCE(MAX(version_number), 0)
		FROM recipe_versionsV1
		WHERE recipe_id = ?
		`,
		primaryName, variantName, creatorID,
	)
}

func InsertNewRecipeVersionIntoRecipeVersionTable(tx sqlExecutor, primaryName, variantName, creatorID string, maxVersion int) (sql.Result, error) {
	return tx.Exec(
		`
		INSERT INTO recipe_versionsV1 (recipe_id, version_number)
		VALUES (?, ?)
		`,
		primaryName, variantName, creatorID, maxVersion+1,
	)
}

func GetIngredientsFromIngredientsTable(q sqlExecutor, primaryName, variantName, creatorID string) (*sql.Rows, error) {
	return q.Query(
		`
		SELECT name, quantity, unit
		FROM ingredientsV1
		WHERE recipe_primary_name = ?
		AND recipe_variant_name = ?
		AND recipe_creator_id = ?
		ORDER BY name
		`,
		primaryName, variantName, creatorID,
	)
}

// TODO: Get step ingredients to join with the corresponding instruction (see structs and the database)
func GetStepsFromInstructionsTable(tx sqlExecutor, primaryName, variantName, creatorID string) (*sql.Rows, error) {
	return tx.Query(
		`
		SELECT instruction
		FROM instructionsV1
		WHERE recipe_primary_name = ?
		AND recipe_variant_name = ?
		AND recipe_creator_id = ?
		ORDER BY step_number
		`,
		primaryName, variantName, creatorID,
	)
}

func GetVersionsFromRecipeVersionsTable(s *RecipeServiceV1, primaryName, variantName, creatorID string) (*sql.Rows, error) {
	return s.DB.Query(
		`
		SELECT id, version_number, created_at FROM recipe_versionsV1
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
		FROM recipe_versionsV1 rv
		JOIN recipesV1 r ON r.id = rv.recipe_id
		WHERE rv.id = ? AND rv.recipe_id = ? AND r.user_id = ?
		`,
		versionID, primaryName, variantName, creatorID, userID,
	)
}

func GetStepIngredientsFromStepIngredientsTable(s *RecipeServiceV1, primaryName, variantName, creatorID string) (*sql.Rows, error) {
	return s.DB.Query(
		`
		SELECT recipe_primary_name, recipe_variant_name, recipe_creator_id, step_number, name, amount, unit
		FROM step_ingredientsV1
		WHERE recipe_primary_name = ?
		AND recipe_variant_name = ?
		AND recipe_creator_id = ?
		`,
		primaryName, variantName, creatorID,
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
            r.primary_name,
			r.variant_name,
			r.creator_id,
            0 AS version_id,
            COALESCE(r.description, '') AS description,
            COALESCE(r.image_url, '') AS image_url,
			COALESCE(
				(SELECT GROUP_CONCAT(t.name, ',')
				FROM tagsV1 t
				JOIN recipeTagsV1 rt ON rt.recipe_tag_name = t.name
				WHERE rt.recipe_primary_name = r.primary_name
				AND rt.recipe_variant_name = r.variant_name
				AND rt.recipe_creator_id = r.creator_id),
				''
			)
        FROM recipesV1 r
     	WHERE r.creator_id = ?
    	ORDER BY r.created_at DESC
		`,
		userID,
	)
}

func GetLatestVersionIDFromRecipeVersionsTable(tx sqlExecutor, primaryName, variantName, creatorID string) *sql.Row {
	return tx.QueryRow(
		`
        SELECT version_number
        FROM recipe_versionsV1
        WHERE recipe_primary_name = ?
		AND recipe_variant_name = ?
		AND recipe_creator_id = ?
        ORDER BY version_number DESC
        LIMIT 1
    	`,
		primaryName, variantName, creatorID,
	)
}

func GetUserFromRecipesTable(s *RecipeServiceV1, recipeID int64) *sql.Row {
	return s.DB.QueryRow(
		`
		SELECT user_id
		FROM recipesV1
		WHERE id = ?
		`,
		recipeID,
	)
}

func SearchByTag(conditions []string) []string {
	return append(conditions,
		`
		EXISTS (
			SELECT 1
			FROM tagsV1 t JOIN recipeTagsV1 rt ON rt.tag_id = t.id
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

func CallSearchQuery(s *RecipeServiceV1, args []any, conditions []string, query string) (*sql.Rows, error) {
	args = append(args, "%"+query+"%", "%"+query+"%", "%"+strings.ToLower(query)+"%", "%"+query+"%", "%"+query+"%")

	searchQuery := `
		SELECT r.id, r.user_id, r.title, COALESCE(r.description, ''), COALESCE(r.image_url, ''),
		COALESCE((SELECT GROUP_CONCAT(t.name, ',') FROM tagsV1 t JOIN recipeTagsV1 rt ON rt.tag_id = t.id WHERE rt.recipe_id = r.id), '')
		FROM recipesV1 r WHERE ` + strings.Join(conditions, " AND ") + `
		ORDER BY CASE WHEN LOWER(r.title) LIKE LOWER(?) THEN 0 ELSE 1 END, r.created_at DESC
	`
	args = append(args, "%"+query+"%")
	return s.DB.Query(searchQuery, args...)
}

func GetAllRecipesFromRecipesTable(s *RecipeServiceV1) (*sql.Rows, error) {
	return s.DB.Query(
		`
		SELECT r.primary_name, r.variant_name, r.creator_id, COALESCE(r.description, ''), COALESCE(r.image_url, ''),
		COALESCE((
			SELECT GROUP_CONCAT(t.name, ',')
			FROM tagsV1 t JOIN recipeTagsV1 rt ON rt.recipe_tag_name = t.name
			WHERE rt.recipe_primary_name = r.primary_name
			AND rt.recipe_variant_name = r.variant_name
			AND rt.recipe_creator_id = r.creator_id
			), '')
		FROM recipesV1 r
		ORDER BY r.created_at DESC
		`,
	)
}

func GetRecipeFromRecipeTable(s *RecipeServiceV1, primaryName, variantName, creatorID string) *sql.Row {
	return s.DB.QueryRow(
		`
		SELECT primary_name, variant_name, creator_id, COALESCE(description, ''), COALESCE(image_url, ''), COALESCE(servings, 0), COALESCE(prep_time_minutes, 0)
		FROM recipesV1
		WHERE primary_name = ?
		AND variant_name = ?
		AND creator_id = ?
		`,
		primaryName, variantName, creatorID,
	)
}

func DeleteFromUserShoppingListTable(tx sqlExecutor, primaryName, variantName, creatorID string) (sql.Result, error) {
	return tx.Exec(
		`
		DELETE FROM userShoppingListV2
		WHERE (source_recipe_primary_name, source_recipe_variant_name, source_recipe_creator_id) IN (
			SELECT recipe_primary_name, recipe_variant_name, recipe_creator_id
			FROM recipe_versionsV1
			WHERE recipe_primary_name = ?
			AND recipe_variant_name = ?
			AND recipe_creator_id = ?
		)
		`, primaryName, variantName, creatorID)
}

func DeleteFromUserShoppingStateTable(tx sqlExecutor) (sql.Result, error) {
	return tx.Exec(
		`
    	DELETE FROM userShoppingStateV1
    	WHERE NOT EXISTS (
    		SELECT 1
        	FROM userShoppingListV2
    		WHERE userShoppingListV2.user_id = userShoppingStateV1.user_id
      			AND userShoppingListV2.name = userShoppingStateV1.name
          		AND userShoppingListV2.unit = userShoppingStateV1.unit
    	)
	`)
}

func DeleteFromIngredientsTable(tx sqlExecutor, primaryName, variantName, creatorID string) (sql.Result, error) {
	return tx.Exec(
		`
		DELETE FROM ingredientsV1
		WHERE (recipe_primary_name, recipe_variant_name, recipe_creator_id) IN (
			SELECT recipe_primary_name, recipe_variant_name, recipe_creator_id 
			FROM recipe_versionsV1
			WHERE recipe_primary_name = ?
			AND recipe_variant_name = ?
			AND recipe_creator_id = ?
		)
	`, primaryName, variantName, creatorID)
}

func DeleteFromStepIngredientsTable(tx sqlExecutor, primaryName, variantName, creatorID string) (sql.Result, error) {
	return tx.Exec(
		`
		DELETE FROM step_ingredientsV1
		WHERE (recipe_primary_name, recipe_variant_name, recipe_creator_id) IN (
			SELECT recipe_primary_name, recipe_variant_name, recipe_creator_id
			FROM recipe_versionsV1
			WHERE recipe_primary_name = ?
			AND recipe_variant_name = ?
			AND recipe_creator_id = ?
		)
	`, primaryName, variantName, creatorID)
}

func DeleteFromInstructionsTable(tx sqlExecutor, primaryName, variantName, creatorID string) (sql.Result, error) {
	return tx.Exec(
		`
		DELETE FROM instructionsV1
		WHERE (recipe_primary_name, recipe_variant_name, recipe_creator_id) IN (
			SELECT recipe_primary_name, recipe_variant_name, recipe_creator_id 
			FROM recipe_versionsV1
			WHERE recipe_primary_name = ?
			AND recipe_variant_name = ?
			AND recipe_creator_id = ?
		)
	`, primaryName, variantName, creatorID)
}

func DeleteFromRecipeVersionsTable(tx sqlExecutor, primaryName, variantName, creatorID string) (sql.Result, error) {
	return tx.Exec(
		`
		DELETE FROM recipe_versionsV1
		WHERE recipe_primary_name = ?
		AND recipe_variant_name = ?
		AND recipe_creator_id = ?
	`, primaryName, variantName, creatorID)
}

func DeleteFromRecipeTagsTable(tx sqlExecutor, primaryName, variantName, creatorID string) (sql.Result, error) {
	return tx.Exec(
		`
		DELETE FROM recipeTagsV1
		WHERE recipe_primary_name = ?
		AND recipe_variant_name = ?
		AND recipe_creator_id = ?
	`, primaryName, variantName, creatorID)
}

func DeleteFromRecipesTable(tx sqlExecutor, primaryName, variantName, creatorID string) (sql.Result, error) {
	return tx.Exec(
		`
		DELETE FROM recipesV1
		WHERE primary_name = ?
		AND variant_name = ?
		AND creator_id = ?
	`, primaryName, variantName, creatorID)
}

func UpdateRecipeDetailsToRecipeTable(tx sqlExecutor, data RecipeUpdateV1, primaryName, variantName, creatorID string) (sql.Result, error) {
	return tx.Exec(
		`
		UPDATE recipesV1
		SET title = ?, description = ?, image_url = COALESCE(NULLIF(?, ''), image_url), servings = ?, prep_time_minutes = ?
		WHERE id = ?
	`, data.Title, data.Description, data.ImageURL, data.Servings, data.PrepTimeMinutes, primaryName, variantName, creatorID)
}

func InsertIntoInstructionTableWithTx(tx sqlExecutor, step RecipeStepV1, primaryName, variantName, creatorID string) (sql.Result, error) {
	return tx.Exec(
		` 
		INSERT INTO instructionsV1 (recipe_version_id, step_number, instruction, notes)
		VALUES (?, ?, ?, ?)
	`, primaryName, variantName, creatorID, step.Instruction)
}

func InsertIntoStepIngredientsTableWithTx(tx sqlExecutor, si RecipeStepIngredientV1, primaryName, variantName, creatorID string) (sql.Result, error) {
	return tx.Exec(
		`
		INSERT INTO step_ingredientsV1 (recipe_id, step_id, step_ingredient)
		VALUES (?, ?, ?)
	`, primaryName, variantName, creatorID, si.Name, si.Aliases, si.Amount, si.Unit)
}

func InsertIntoIngredientsTableWithTx(tx sqlExecutor, ing IngredientV1, primaryName, variantName, creatorID string) (sql.Result, error) {
	return tx.Exec(
		`
        INSERT INTO ingredientsV1 (recipe_version_id, name, quantity, unit)
		VALUES (?, ?, ?, ?)
    `, primaryName, variantName, creatorID, ing.Name, ing.Amount, ing.Unit)
}

func GetUserForUpdateRecipe(tx sqlExecutor, primaryName, variantName, creatorID, userID string) *sql.Row {
	return tx.QueryRow(
		`
		SELECT user_id
		FROM recipesV1
		WHERE id = ? AND user_id = ? 
	`, primaryName, variantName, creatorID, userID)
}

func GetCookBookRecipesFromCookBookTable(s *RecipeServiceV1, userID string) (*sql.Rows, error) {
	return s.DB.Query(
		`
		SELECT 
			r.id, 
			r.user_id, 
			r.title, 
			COALESCE(r.description, ''), 
			COALESCE(r.image_url, ''), 
			COALESCE(
				(
					SELECT GROUP_CONCAT(t.name, ',') 
					FROM tagsV1 t 
					JOIN recipeTagsV1 rt ON rt.tag_id = t.id 
					WHERE rt.recipe_id = r.id
				), 
				''
			), 
			COALESCE(r.servings,0), 
			COALESCE(r.prep_time_minutes, 0) 
		FROM cookBookV1 cb 
		JOIN recipesV1 r on r.id = cb.recipe_id 
		WHERE cb.user_id = ? 
		ORDER BY cb.id DESC
	`, userID)
}

func GetItemsFromShoppingListTable(q sqlExecutor, userID string) (*sql.Rows, error) {
	return q.Query(
		`
		SELECT sl.name, sl.unit, sl.quantity,
		    COALESCE(r.id, 0), COALESCE(r.title, ''), COALESCE(r.image_url, '')
		FROM userShoppingListV2 sl
		LEFT JOIN recipe_versionsV1 rv ON rv.id = sl.source_recipe_version_id
		LEFT JOIN recipesV1 r ON r.id = rv.recipe_id
		WHERE sl.user_id = ?
		ORDER BY sl.name, sl.unit, r.title
	`, userID)
}

func GetPantryAmountsFromUserPantryTable(q sqlExecutor, userID string) (*sql.Rows, error) {
	return q.Query(
		`
		SELECT name, unit, quantity
		FROM userPantryV1
		WHERE user_id = ?
	`, userID)
}

func GetItemShoppingStateFromUserShoppingStateTable(q sqlExecutor, userID string) (*sql.Rows, error) {
	return q.Query(
		`
		SELECT name, unit, checked, bought_qty, bought_unit 
		FROM userShoppingStateV1 
		WHERE user_id = ?
	`, userID)
}

func InsertIntoUserShoppingStateTable(s *ShoppingListService, userID, name, unit string, checked bool) (sql.Result, error) {
	return s.DB.Exec(
		`
		INSERT INTO userShoppingStateV1 (user_id, name, unit, checked)
		VALUES (?, ?, ?, ?)
		ON CONFLICT(user_id, name, unit) DO UPDATE SET checked = excluded.checked
	`, userID, name, unit, checked)
}

func UpdateUserShoppingStateTable(s *ShoppingListService, userID string) (sql.Result, error) {
	return s.DB.Exec(
		`
		UPDATE userShoppingStateV1
		SET checked = 0
		WHERE user_id = ?
	`, userID)
}

func InsertIntoUserShoppingStateTableForBought(s *ShoppingListService, userID, name, unit, qty, qtyUnit string) (sql.Result, error) {
	return s.DB.Exec(
		`
		INSERT INTO userShoppingStateV1 (user_id, name, unit, bought_qty, bought_unit)
		VALUES (?, ?, ?, ?, ?)
		ON CONFLICT(user_id, name, unit) DO UPDATE SET
		    bought_qty = excluded.bought_qty,
		    bought_unit = excluded.bought_unit
	`, userID, name, unit, qty, qtyUnit)
}

func GetRecipesFromShoppingListTable(s *ShoppingListService, userID string) (*sql.Rows, error) {
	return s.DB.Query(
		`
		SELECT DISTINCT r.id, r.title, COALESCE(r.image_url, ''), COALESCE(r.servings, 0)
		FROM userShoppingListV2 sl
		JOIN recipe_versionsV1 rv ON rv.id = sl.source_recipe_version_id
		JOIN recipesV1 r ON r.id = rv.recipe_id
		WHERE sl.user_id = ?
		ORDER BY r.title
	`, userID)
}

func GetOutdatedRecipes(s *ShoppingListService, userID string) (*sql.Rows, error) {
	return s.DB.Query(
		`
		SELECT rv.recipe_id, MAX(sl.source_recipe_version_id)
		FROM userShoppingListV2 sl
		JOIN recipe_versionsV1 rv ON rv.id = sl.source_recipe_version_id
		WHERE sl.user_id = ?
		GROUP BY rv.recipe_id
	`, userID)
}

func SelectExistsFromShoppingListTable(s *ShoppingListService, userID, primaryName, variantName, creatorID string) *sql.Row {
	return s.DB.QueryRow(
		`
		SELECT EXISTS (
		    SELECT 1 FROM userShoppingListV2 sl
		    JOIN recipe_versionsV1 rv ON (
				rv.recipe_primary_name = sl.source_recipe_primary_name
				AND rv.recipe_variant_name = source_recipe_variant_name
				AND rv.recipe_creator_id = source_recipe_creator_id
			)
		    WHERE sl.user_id = ?
			AND rv.recipe_primary_name = ?
			AND rv.recipe_variant_name = ?
			AND rv.recipe_creator_id = ?
		)
	`, userID, primaryName, variantName, creatorID)
}

func DeleteFromUserShoppingListWhenAddingIngredient(tx *sql.Tx, userID string, versionID int64) (sql.Result, error) {
	return tx.Exec(
		`
		DELETE FROM userShoppingListV2
		WHERE user_id = ?
		AND source_recipe_version_id IN (
		    SELECT id
			FROM recipe_versionsV1
		    WHERE recipe_id = (
				SELECT recipe_id
				FROM recipe_versionsV1
				WHERE id = ?
			)
		)
	`, userID, versionID)
}

func InsertIntoUserShoppingListTable(tx *sql.Tx, ing IngredientV1, userID string, versionID int64) (sql.Result, error) {
	return tx.Exec(
		`
		INSERT INTO userShoppingListV2 (user_id, name, quantity, unit, source_recipe_version_id)
		VALUES (?, ?, ?, ?, ?)
		ON CONFLICT(user_id, name, unit, source_recipe_version_id)
		DO UPDATE SET quantity = excluded.quantity
	`, userID, ing.Name, ing.Amount, ing.Unit, versionID)
}

func DeleteFromShoppingListWhenRemovingItem(q sqlExecutor, userID, name, unit string) (sql.Result, error) {
	return q.Exec(
		`
		DELETE FROM userShoppingListV2
		WHERE user_id = ?
		AND name = ?
		AND unit = ?
	`, userID, name, unit)
}

func DeleteFromShoppingStateWhenRemovingItem(q sqlExecutor, userID, name, unit string) (sql.Result, error) {
	return q.Exec(
		`
		DELETE FROM userShoppingStateV1
		WHERE user_id = ?
		AND name = ?
		AND unit = ?
	`, userID, name, unit)
}

func DeleteFromShoppingStateWhenRemovingUnusedState(q sqlExecutor, userID string) (sql.Result, error) {
	return q.Exec(
		`
		DELETE FROM userShoppingStateV1
		WHERE user_id = ?
		    AND NOT EXISTS (
		        SELECT 1 FROM userShoppingListV2 sl
		        WHERE sl.user_id = userShoppingStateV1.user_id
		        AND LOWER(TRIM(sl.name)) = LOWER(TRIM(userShoppingStateV1.name))
		        AND LOWER(TRIM(sl.unit)) = LOWER(TRIM(userShoppingStateV1.unit))
		   )
	`, userID)
}

func DeleteFromShoppingListWhenRemovingRecipe(tx sqlExecutor, userID string, recipeID int64) (sql.Result, error) {
	return tx.Exec(
		`
		DELETE FROM userShoppingListV2
		WHERE user_id = ?
		AND source_recipe_version_id IN (
			SELECT id
			FROM recipe_versionsV1
			WHERE recipe_id = ?
		)
	`, userID, recipeID)
}

func GetCookBookFromCookBookTable(s *CookBookService, userID string) (*sql.Rows, error) {
	return s.db.Query(
		`
		SELECT id, user_id, recipe_id, source_recipe_version_id
		FROM cookBookV1
		WHERE user_id = ?
	`, userID)
}

func InsertIntoCookBookTable(s *CookBookService, userID, primaryName, variantName, creatorID string) (sql.Result, error) {
	return s.db.Exec(
		`
		INSERT INTO cookBookV1 (user_id, recipe_id)
		VALUES (?, ?) ON CONFLICT(user_id, recipe_id) DO NOTHING
	`, userID, primaryName, variantName, creatorID)
}

func DeleteFromCookBookTable(s *CookBookService, userID, primaryName, variantName, creatorID string) (sql.Result, error) {
	return s.db.Exec(
		`
		DELETE FROM cookBookV1
		WHERE user_id = ? AND recipe_id = ?
		`, userID, primaryName, variantName, creatorID)
}

func GetCountFromCookBookTable(s *CookBookService, count int, userID, primaryName, variantName, creatorID string) error {
	return s.db.Get(&count,
		`
		SELECT COUNT(*)
		FROM cookBookV1
		WHERE user_id = ?
		AND recipe_primary_name = ?
		AND recipe_variant_name = ?
		AND recipe_creator_id = ?
	`, userID, primaryName, variantName, creatorID)
}

func GetItemsFromUserPantryTable(s *PantryService, userID string) (*sql.Rows, error) {
	return s.DB.Query(
		`
		SELECT rowid, name, quantity, unit
		FROM userPantryV1
		WHERE user_id = ?
		ORDER BY name, unit
	`, userID)
}

func GetPantryItemsWhenAddingItem(q sqlExecutor, userID, name string) (*sql.Rows, error) {
	return q.Query(
		`SELECT name, quantity, unit
		FROM userPantryV1
		WHERE user_id = ?
		AND name = ?
		COLLATE NOCASE
	`, userID, name)
}

func UpdateUserPantryTable(q sqlExecutor, existingName, existingUnit, combinedQty, combinedUnit, userID string) (sql.Result, error) {
	return q.Exec(
		`
		UPDATE userPantryV1 SET quantity = ?, unit = ?
		WHERE user_id = ?
		AND name = ?
		AND unit = ?
	`, combinedQty, combinedUnit, userID, existingName, existingUnit)
}

func InsertIntoUserPantryTable(q sqlExecutor, userID, name, quantity, unit string) (sql.Result, error) {
	return q.Exec(
		`
		INSERT INTO userPantryV1 (user_id, name, quantity, unit)
		VALUES (?, ?, ?, ?)
		ON CONFLICT(user_id, name, unit) DO UPDATE SET quantity = excluded.quantity
	`, userID, name, quantity, unit)
}

func DeleteFromUserPantryTable(s *PantryService, userID, name, unit string) (sql.Result, error) {
	return s.DB.Exec(
		`
		DELETE FROM userPantryV1
		WHERE user_id = ?
		AND name = ?
		AND unit = ?
	`, userID, name, unit)
}

func InsertIntoUsersTable(s *UserServiceV1, username, email, passwordHash string) (sql.Result, error) {
	return s.DB.Exec(
		`
		INSERT INTO usersV1(username, email, password_hash) 
		VALUES (?, ?, ?)
	`, username, email, passwordHash)
}

func GetPasswordHash(s *UserServiceV1, email string) *sql.Row {
	return s.DB.QueryRow(
		`
		SELECT username, password_hash
		FROM usersV1
		WHERE email = ?
	`, email)
}

func GetUsername(s *UserServiceV1, id string) *sql.Row {
	return s.DB.QueryRow(
		`
		SELECT username
		FROM usersV1
		WHERE username = ?
	`, id)
}

func InsertIntoSessionsTable(s *UserServiceV1, sessionID, expires, id string) (sql.Result, error) {
	return s.DB.Exec(
		`
		INSERT INTO sessionsV1(id, user_id, expires_at)
		VALUES (?, ?, ?)
	`, sessionID, id, expires)
}

func DeleteFromSessionsTable(s *UserServiceV1, val string) (sql.Result, error) {
	return s.DB.Exec(
		`
		DELETE FROM sessionsV1
		WHERE id = ?
	`, val)
}

func GetUserIDFromSessionsTable(s *UserServiceV1, val string) *sql.Row {
	return s.DB.QueryRow(
		`
		SELECT user_id, expires_at
		FROM sessionsV1
		WHERE id = ?
	`, val)
}

func GetUserIDFromUsersTableByEmail(s *UserServiceV1, email string) *sql.Row {
	return s.DB.QueryRow(
		`SELECT id FROM usersV1 WHERE email = ?
	`, email)
}

func InsertIntoPassResetTable(s *UserServiceV1, userID, token, expires string) (sql.Result, error) {
	return s.DB.Exec(
		`
		INSERT INTO passResetV1(user_id, token, expires_at)
		VALUES (?, ?, ?)
	`, userID, token, expires)
}

func GetUserIDFromPassResetTable(s *UserServiceV1, token string) *sql.Row {
	return s.DB.QueryRow(
		`
		SELECT user_id, expires_at
		FROM passResetV1
		WHERE token = ?
	`, token)
}

func UpdateUsersTable(s *UserServiceV1, userID, hash string) (sql.Result, error) {
	return s.DB.Exec(
		`
		UPDATE usersV1 SET password_hash = ?
		WHERE id = ?
	`, hash, userID)
}

func DeleteFromPassResetTable(s *UserServiceV1, token string) (sql.Result, error) {
	return s.DB.Exec(
		`
		DELETE FROM passResetV1
		WHERE token = ?
	`, token)
}

func GetEmailFromUsersTable(s *UserServiceV1, username string) *sql.Row {
	return s.DB.QueryRow(
		`
		SELECT email FROM usersV1
		WHERE username = ?
	`, username)
}

func InsertIntoEmailVerifyTable(s *UserServiceV1, userID, token, expires string) (sql.Result, error) {
	return s.DB.Exec(
		`
		INSERT INTO emailVerifyV1(user_id, token, expires_at)
		VALUES (?, ?, ?)
	`, userID, token, expires)
}

func GetUserIDFromEmailVerifyTable(s *UserServiceV1, token string) *sql.Row {
	return s.DB.QueryRow(
		`
		SELECT user_id, expires_at
		FROM emailVerifyV1
		WHERE token = ?
	`, token)
}

func DeleteFromEmailVerifyTable(s *UserServiceV1, token string) (sql.Result, error) {
	return s.DB.Exec(
		`
		DELETE FROM emailVerifyV1 WHERE token = ?
	`, token)
}

func UpdateUsersTableWithVerification(s *UserServiceV1, userID string) (sql.Result, error) {
	return s.DB.Exec(
		`
		UPDATE usersV1 SET is_verified = TRUE
		WHERE username = ?
	`, userID)
}

func GetIsUserVerified(s *UserServiceV1, userID string) *sql.Row {
	return s.DB.QueryRow(
		`
		SELECT is_verified
		FROM usersV1
		WHERE username = ?
	`, userID)
}

func GetTagFromTagsTable(tx sqlExecutor, tag string) *sql.Row {
	return tx.QueryRow(
		`
		SELECT name 
		FROM tagsV1 WHERE name = ?`,
		tag,
	)
}
