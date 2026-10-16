package services

import (
	"database/sql"
	"errors"
	"fmt"
	"log"
	"slices"
	"strings"
	"time"

	"github.com/jmoiron/sqlx"
)

var ErrRecipeNotFound = errors.New("recipe not found or access denied")

type RecipeInfo struct {
	ID              int64 // recipe ID
	VersionID       int64 // current version ID
	Title           string
	Description     string
	ImageURL        string
	UserID          int64
	Servings        int
	PrepTimeMinutes int
	Tags            []string
}

type RecipeEditPageData struct {
	Recipe      RecipeInfo
	Ingredients []Ingredient
	Steps       []Step
}

type Ingredient struct {
	ID              int64
	RecipeVersionID int64
	Name            string
	Quantity        string
	Unit            string
}

type Step struct {
	ID              int64
	RecipeVersionID int64
	StepNumber      int
	Instruction     string
	Notes           string
}

type RecipeVersion struct {
	ID            int64
	VersionNumber int
	CreatedAt     time.Time
}

type RecipeUpdate struct {
	Title           string
	Description     string
	Tags            []string
	Servings        int
	PrepTimeMinutes int
	Ingredients     []Ingredient
	Steps           []Step
}

type RecipeService struct {
	DB *sqlx.DB
}

var PresetTags = []string{
	// Meal type
	"breakfast", "brunch", "lunch", "dinner", "appetizer", "snack", "dessert", "side-dish", "soup", "salad", "sandwich", "wrap", "burger", "tacos", "pizza", "pasta", "bowl", "curry", "casserole", "stir-fry", "roast", "smoothie", "cocktail",
	// Dietary / lifestyle
	"vegetarian", "vegan", "pescatarian", "gluten-free", "dairy-free", "egg-free", "peanut-free", "nut-free", "soy-free", "sesame-free", "shellfish-free", "fish-free", "wheat-free", "halal", "kosher", "paleo", "keto", "low-carb", "low-sugar", "sugar-free", "high-protein", "high-fiber", "low-sodium", "low-fat", "heart-healthy", "diabetic-friendly", "anti-inflammatory", "low-fodmap", "low-calories", "lactose-free", "grain-free",
	// Cooking method
	"quick", "easy", "one-pot", "one-pan", "meal-prep", "air-fryer", "slow-cooker", "instant-pot", "oven-baked", "sheet-pan", "no-bake", "skillet", "stovetop", "make-ahead", "freezer-friendly", "pressure-cooker",
	// Cuisine
	"italian", "mexican", "american", "mediterranean", "indian", "japanese", "chinese", "thai", "korean", "french", "greek", "spanish", "lebanese", "moroccan", "caribbean", "african", "vietnamese", "filipino", "brazilian", "tex-mex", "cajun", "soul-food", "middle-eastern", "latin-american",
	// Flavor / occasion
	"spicy", "savory", "sweet", "sour", "smoky", "garlicky", "herby", "citrusy", "kid-friendly", "party-food", "date-night", "holiday", "comfort-food", "fresh", "summer", "winter", "fall", "spring",
}

type PresetTagGroup struct {
	Name string
	Tags []string
}

var PresetTagGroups = []PresetTagGroup{
	{Name: "Meal type", Tags: []string{"breakfast", "brunch", "lunch", "dinner", "appetizer", "snack", "dessert", "side-dish", "soup", "salad", "sandwich", "wrap", "burger", "tacos", "pizza", "pasta", "bowl", "curry", "casserole", "stir-fry", "roast", "smoothie", "cocktail"}},
	{Name: "Dietary", Tags: []string{"vegetarian", "vegan", "pescatarian", "gluten-free", "dairy-free", "egg-free", "peanut-free", "nut-free", "soy-free", "sesame-free", "shellfish-free", "fish-free", "wheat-free", "halal", "kosher", "paleo", "keto", "low-carb", "low-sugar", "sugar-free", "high-protein", "high-fiber", "low-sodium", "low-fat", "heart-healthy", "diabetic-friendly", "anti-inflammatory", "low-fodmap", "low-calories", "lactose-free", "grain-free"}},
	{Name: "Cooking method", Tags: []string{"quick", "easy", "one-pot", "one-pan", "meal-prep", "air-fryer", "slow-cooker", "instant-pot", "oven-baked", "sheet-pan", "no-bake", "skillet", "stovetop", "make-ahead", "freezer-friendly", "pressure-cooker"}},
	{Name: "Cuisine", Tags: []string{"italian", "mexican", "american", "mediterranean", "indian", "japanese", "chinese", "thai", "korean", "french", "greek", "spanish", "lebanese", "moroccan", "caribbean", "african", "vietnamese", "filipino", "brazilian", "tex-mex", "cajun", "soul-food", "middle-eastern", "latin-american"}},
	{Name: "Flavor & occasion", Tags: []string{"spicy", "savory", "sweet", "sour", "smoky", "garlicky", "herby", "citrusy", "kid-friendly", "party-food", "date-night", "holiday", "comfort-food", "fresh", "summer", "winter", "fall", "spring"}},
}

func NewRecipeService(db *sqlx.DB) *RecipeService {
	return &RecipeService{DB: db}
}

func (s *RecipeService) CreateRecipe(userID int, title, imageURL string, description string, servings int, prepTimeMinutes int) (int64, error) {
	result, err := s.DB.Exec(
		"INSERT INTO recipesV1(user_id, title, image_url, description, servings, prep_time_minutes) VALUES (?, ?, ?, ?, ?, ?)",
		userID,
		title,
		imageURL,
		description,
		servings,
		prepTimeMinutes,
	)
	if err != nil {
		return 0, err
	}

	recipeID, err := result.LastInsertId()
	if err != nil {
		return 0, err
	}

	_, err = s.DB.Exec( // creates the first version
		`INSERT INTO recipe_versionsV1 (recipe_id, version_number)
         VALUES (?, 1)`,
		recipeID,
	)
	if err != nil {
		return 0, err
	}
	return recipeID, nil
}

func (s *RecipeService) SaveTags(tx sqlExecutor, recipeID int64, tags []string) error {
	allowedTags := make(map[string]struct{}, len(PresetTags))

	for _, presetTag := range PresetTags {
		allowedTags[presetTag] = struct{}{}
	}
	seen := make(map[string]struct{})

	for _, rawTag := range tags {
		tag := strings.ToLower(strings.TrimSpace(rawTag))
		if tag == "" {
			continue
		}
		if _, allowed := allowedTags[tag]; !allowed {
			continue
		}
		if _, ok := seen[tag]; ok {
			continue
		}
		seen[tag] = struct{}{}

		_, err := tx.Exec(`
			INSERT INTO tagsV1(name) VALUES (?) ON CONFLICT(name) DO NOTHING`,
			tag,
		)
		if err != nil {
			return err
		}

		var tagID int64
		if err := tx.QueryRow(`
			SELECT id 
			FROM tagsV1 WHERE name = ?`,
			tag,
		).Scan(&tagID); err != nil {
			return err
		}

		if _, err := tx.Exec(
			`INSERT OR IGNORE INTO recipeTagsV1(recipe_id, tag_id) VALUES (?, ?)`,
			recipeID, tagID,
		); err != nil {
			return err
		}
	}
	return nil
}

func splitTags(value string) []string {
	if value == "" {
		return nil
	}
	return strings.Split(value, ",")
}

func (s *RecipeService) BatchSaveIngredients(versionID int64, names, quantities, units []string) error {
	for i, name := range names {
		if name == "" {
			continue
		}
		qty := ""
		if i < len(quantities) {
			qty = quantities[i]
		}
		unit := ""
		if i < len(units) {
			unit = units[i]
		}
		_, err := s.DB.Exec(
			"INSERT INTO ingredientsV1 (recipe_version_id, name, quantity, unit) VALUES (?, ?, ?, ?)",
			versionID, name, qty, unit,
		)
		if err != nil {
			return err
		}
	}
	return nil
}

func (s *RecipeService) BatchSaveSteps(versionID int64, instructions, notes []string) error {
	for i, instruction := range instructions {
		if instruction == "" {
			continue
		}
		note := ""
		if i < len(notes) {
			note = notes[i]
		}
		_, err := s.DB.Exec(
			"INSERT INTO instructionsV1 (recipe_version_id, step_number, instruction, notes) VALUES (?, ?, ?, ?)",
			versionID, i+1, instruction, note,
		)
		if err != nil {
			return err
		}
	}
	return nil
}

func (s *RecipeService) NewVersion(tx sqlExecutor, recipeID int64) (int64, error) {
	var maxVersion int
	if err := tx.QueryRow(
		"SELECT COALESCE(MAX(version_number), 0) FROM recipe_versionsV1 WHERE recipe_id = ?",
		recipeID,
	).Scan(&maxVersion); err != nil {
		return 0, err
	}

	result, err := tx.Exec(
		"INSERT INTO recipe_versionsV1 (recipe_id, version_number) VALUES (?, ?)",
		recipeID, maxVersion+1,
	)
	if err != nil {
		return 0, err
	}
	return result.LastInsertId()
}

func (s *RecipeService) GetIngredients(q sqlExecutor, recipeVersionID int64) ([]Ingredient, error) {
	var ingredients []Ingredient
	rows, err := q.Query(
		"SELECT id, recipe_version_id, name, quantity, unit FROM ingredientsV1 WHERE recipe_version_id = ? ORDER BY id", recipeVersionID,
	)
	if err != nil {
		return nil, err
	}

	defer func() {
		if err := rows.Close(); err != nil {
			log.Println("Error closing rows:", err)
		}
	}()

	for rows.Next() {
		var i Ingredient
		if err := rows.Scan(&i.ID, &i.RecipeVersionID, &i.Name, &i.Quantity, &i.Unit); err != nil {
			return nil, err
		}
		ingredients = append(ingredients, i)
	}
	return ingredients, rows.Err()
}

func (s *RecipeService) GetSteps(tx sqlExecutor, recipeVersionID int64) ([]Step, error) {
	var steps []Step
	rows, err := tx.Query(`
		SELECT id, recipe_version_id, step_number, instruction, COALESCE(notes, '') 
		FROM instructionsV1 WHERE recipe_version_id = ? 
		ORDER BY step_number
		`, recipeVersionID)
	if err != nil {
		return nil, err
	}

	defer func() {
		if err := rows.Close(); err != nil {
			log.Println("Error closing rows:", err)
		}
	}()

	for rows.Next() {
		var st Step
		if err := rows.Scan(&st.ID, &st.RecipeVersionID, &st.StepNumber, &st.Instruction, &st.Notes); err != nil {
			return nil, err
		}
		steps = append(steps, st)
	}
	return steps, rows.Err()
}

// GetVersions returns every version of a recipe, newest first.
func (s *RecipeService) GetVersions(recipeID int64) ([]RecipeVersion, error) {
	var versions []RecipeVersion
	rows, err := s.DB.Query(
		"SELECT id, version_number, created_at FROM recipe_versionsV1 WHERE recipe_id = ? ORDER BY version_number DESC", recipeID,
	)
	if err != nil {
		return nil, err
	}

	defer func() {
		if err := rows.Close(); err != nil {
			log.Println("Error closing rows:", err)
		}
	}()

	for rows.Next() {
		var v RecipeVersion
		if err := rows.Scan(&v.ID, &v.VersionNumber, &v.CreatedAt); err != nil {
			return nil, err
		}
		versions = append(versions, v)
	}
	return versions, rows.Err()
}

// GetVersion returns one version of a recipe, only if the recipe belongs to userID.
func (s *RecipeService) GetVersion(userID int, recipeID int64, versionID int64) (RecipeVersion, error) {
	var v RecipeVersion
	err := s.DB.QueryRow(`
		SELECT rv.id, rv.version_number, rv.created_at
		FROM recipe_versionsV1 rv
		JOIN recipesV1 r ON r.id = rv.recipe_id
		WHERE rv.id = ? AND rv.recipe_id = ? AND r.user_id = ?
	`, versionID, recipeID, userID).Scan(&v.ID, &v.VersionNumber, &v.CreatedAt)

	if errors.Is(err, sql.ErrNoRows) {
		return v, ErrRecipeNotFound
	}
	return v, err
}

func (s *RecipeService) GetRecipesByUser(userID int) ([]RecipeInfo, error) {
	rows, err := s.DB.Query(
		// `SELECT r.id, r.title, COALESCE(rv.id, 0)
		//  FROM recipesV1 r
		//  LEFT JOIN recipe_versionsV1 rv ON rv.recipe_id = r.id
		//    AND rv.version_number = (SELECT MAX(version_number) FROM recipe_versionsV1 WHERE recipe_id = r.id)
		//  WHERE r.user_id = ?
		//  ORDER BY r.created_at DESC`,
		`SELECT
            r.id,
            r.title,
			r.user_id,
            0 AS version_id,
            COALESCE(r.description, '') AS description,
            COALESCE(r.image_url, '') AS image_url,
			COALESCE(
				(SELECT GROUP_CONCAT(t.name, ',')
				FROM tagsV1 t
				JOIN recipeTagsV1 rt ON rt.tag_id = t.id
				WHERE rt.recipe_id = r.id),
				''
			)
         FROM recipesV1 r
         WHERE r.user_id = ?
         ORDER BY r.created_at DESC`,
		userID,
	)
	if err != nil {
		return nil, err
	}

	// defer rows.Close()
	defer func() {
		if err := rows.Close(); err != nil {
			log.Println("Error closing rows:", err)
		}
	}()

	var recipes []RecipeInfo
	for rows.Next() {
		var ri RecipeInfo
		var tags string
		// if err := rows.Scan(&ri.ID, &ri.Title, &ri.VersionID); err != nil {
		// 	return nil, err
		// }
		if err := rows.Scan(&ri.ID, &ri.Title, &ri.UserID, &ri.VersionID, &ri.Description, &ri.ImageURL, &tags); err != nil {
			return nil, err
		}
		ri.Tags = splitTags(tags)
		recipes = append(recipes, ri)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return recipes, nil
}

func (s *RecipeService) GetLatestVersionID(tx sqlExecutor, recipeID int64) (int64, error) {

	var versionID int64

	err := tx.QueryRow(`
        SELECT id
        FROM recipe_versionsV1
        WHERE recipe_id = ?
        ORDER BY version_number DESC
        LIMIT 1
    `, recipeID).Scan(&versionID)

	if err != nil {
		return 0, fmt.Errorf(
			"failed to get latest version: %w", err,
		)
	}

	return versionID, nil
}

func (s *RecipeService) Search(query string, tagFilters []string, maxTime int) ([]RecipeInfo, error) {
	query = strings.TrimSpace(query)
	conditions := make([]string, 0, len(tagFilters)+2)
	args := make([]any, 0, len(tagFilters)+6)
	seenTags := make(map[string]struct{})
	for _, tag := range tagFilters {
		tag = strings.ToLower(strings.TrimSpace(tag))
		if tag == "" {
			continue
		}
		if _, seen := seenTags[tag]; seen {
			continue
		}
		seenTags[tag] = struct{}{}
		conditions = append(conditions, `EXISTS (
			SELECT 1 FROM tagsV1 t JOIN recipeTagsV1 rt ON rt.tag_id = t.id
			WHERE rt.recipe_id = r.id AND t.name = ?
		)`)
		args = append(args, tag)
	}
	if maxTime > 0 {
		conditions = append(conditions, "r.prep_time_minutes IS NOT NULL AND r.prep_time_minutes <= ?")
		args = append(args, maxTime)
	}

	conditions = append(conditions, `(r.title LIKE ? OR r.description LIKE ? OR EXISTS (
		SELECT 1 FROM tagsV1 t JOIN recipeTagsV1 rt ON rt.tag_id = t.id
		WHERE rt.recipe_id = r.id AND t.name LIKE ?
	) OR EXISTS (
		SELECT 1 FROM ingredientsV1 i
		JOIN recipe_versionsV1 rv ON rv.id = i.recipe_version_id
		WHERE rv.recipe_id = r.id
		  AND rv.version_number = (SELECT MAX(version_number) FROM recipe_versionsV1 WHERE recipe_id = r.id)
		  AND i.name LIKE ?
	))`)
	args = append(args, "%"+query+"%", "%"+query+"%", "%"+strings.ToLower(query)+"%", "%"+query+"%", "%"+query+"%")

	searchQuery := `SELECT r.id, r.user_id, r.title, COALESCE(r.description, ''), COALESCE(r.image_url, ''),
		COALESCE((SELECT GROUP_CONCAT(t.name, ',') FROM tagsV1 t JOIN recipeTagsV1 rt ON rt.tag_id = t.id WHERE rt.recipe_id = r.id), '')
	 FROM recipesV1 r WHERE ` + strings.Join(conditions, " AND ") +
		` ORDER BY CASE WHEN LOWER(r.title) LIKE LOWER(?) THEN 0 ELSE 1 END, r.created_at DESC`
	args = append(args, "%"+query+"%")

	rows, err := s.DB.Query(searchQuery, args...)
	if err != nil {
		return nil, err
	}

	// defer rows.Close()
	defer func() {
		if err := rows.Close(); err != nil {
			log.Println("Error closing rows:", err)
		}
	}()

	var recipes []RecipeInfo

	for rows.Next() {
		var ri RecipeInfo
		var tags string
		if err := rows.Scan(&ri.ID, &ri.UserID, &ri.Title, &ri.Description, &ri.ImageURL, &tags); err != nil {
			return nil, err
		}
		ri.Tags = splitTags(tags)

		recipes = append(recipes, ri)
	}

	return recipes, nil
}

func (s *RecipeService) GetAllRecipes() ([]RecipeInfo, error) {
	rows, err := s.DB.Query(
		`SELECT r.id, r.user_id, r.title, COALESCE(r.description, ''), COALESCE(r.image_url, ''),
			COALESCE((SELECT GROUP_CONCAT(t.name, ',') FROM tagsV1 t JOIN recipeTagsV1 rt ON rt.tag_id = t.id WHERE rt.recipe_id = r.id), '')
		 FROM recipesV1 r ORDER BY r.created_at DESC`,
	)
	if err != nil {
		return nil, err
	}

	// defer rows.Close()
	defer func() {
		if err := rows.Close(); err != nil {
			log.Println("Error closing rows:", err)
		}
	}()

	var recipes []RecipeInfo

	for rows.Next() {
		var ri RecipeInfo
		var tags string
		if err := rows.Scan(&ri.ID, &ri.UserID, &ri.Title, &ri.Description, &ri.ImageURL, &tags); err != nil {
			return nil, err
		}
		ri.Tags = splitTags(tags)
		recipes = append(recipes, ri)
	}

	return recipes, nil
}

func (s *RecipeService) GetRecipeForView(recipeID int64) (*RecipeEditPageData, int64, error) {
	var title string
	var userID int64
	var description string
	var imageURL string
	var servings int
	var prepTimeMinutes int

	err := s.DB.QueryRow(
		"SELECT title, user_id, COALESCE(description, ''), COALESCE(image_url, ''), COALESCE(servings, 0), COALESCE(prep_time_minutes, 0) FROM recipesV1 WHERE id = ?",
		recipeID,
	).Scan(&title, &userID, &description, &imageURL, &servings, &prepTimeMinutes)
	if err != nil {
		return nil, 0, err
	}

	versionID, err := s.GetLatestVersionID(s.DB, recipeID)
	if err != nil {
		return nil, 0, err
	}

	ingredients, err := s.GetIngredients(s.DB, versionID)
	if err != nil {
		return nil, 0, err
	}

	steps, err := s.GetSteps(s.DB, versionID)
	if err != nil {
		return nil, 0, err
	}

	var tagString string
	if err := s.DB.QueryRow(
		`SELECT COALESCE(GROUP_CONCAT(t.name, ','), '') FROM tagsV1 t
		 JOIN recipeTagsV1 rt ON rt.tag_id = t.id WHERE rt.recipe_id = ?`, recipeID,
	).Scan(&tagString); err != nil {
		return nil, 0, err
	}

	return &RecipeEditPageData{
		Recipe: RecipeInfo{
			ID:              recipeID,
			VersionID:       versionID,
			Title:           title,
			Description:     description,
			ImageURL:        imageURL,
			Servings:        servings,
			PrepTimeMinutes: prepTimeMinutes,
			Tags:            splitTags(tagString),
		},
		Ingredients: ingredients,
		Steps:       steps,
	}, userID, nil
}

func (s *RecipeService) DeleteRecipe(recipeID int64) error {
	return withTx(s.DB, func(tx sqlExecutor) error {

		if _, err := tx.Exec(`
			DELETE FROM userShoppingListV2
			WHERE source_recipe_version_id IN (
				SELECT id
				FROM recipe_versionsV1
				WHERE recipe_id = ?
			)
		`, recipeID); err != nil {
			return err
		}

		if _, err := tx.Exec(`
    		DELETE FROM userShoppingStateV1
    		WHERE NOT EXISTS (
        		SELECT 1
        		FROM userShoppingListV2
        		WHERE userShoppingListV2.user_id = userShoppingStateV1.user_id
          			AND userShoppingListV2.name = userShoppingStateV1.name
          			AND userShoppingListV2.unit = userShoppingStateV1.unit
    		)
		`); err != nil {
			return err
		}

		if _, err := tx.Exec(`
			DELETE FROM ingredientsV1
			WHERE recipe_version_id IN (
				SELECT id 
				FROM recipe_versionsV1
				WHERE recipe_id = ?
			)
		`, recipeID); err != nil {
			return err
		}

		if _, err := tx.Exec(`
			DELETE FROM instructionsV1 
			WHERE recipe_version_id IN (
				SELECT id 
				FROM recipe_versionsV1
				WHERE recipe_id = ?
			)
		`, recipeID); err != nil {
			return err
		}

		if _, err := tx.Exec(`
			DELETE FROM recipe_versionsV1
			WHERE recipe_id = ?
		`, recipeID); err != nil {
			return err
		}

		if _, err := tx.Exec(`
			DELETE FROM recipeTagsV1
			WHERE recipe_id = ?
		`, recipeID); err != nil {
			return err
		}

		if _, err := tx.Exec(`
			DELETE FROM recipesV1
			WHERE id = ?
		`, recipeID); err != nil {
			return err
		}
		return nil
	})
}

func (s *RecipeService) UpdateRecipeDetails(tx sqlExecutor, recipeID int64, data RecipeUpdate) error {
	_, err := tx.Exec(`
		UPDATE recipesV1
		SET title = ?, description = ?, servings = ?, prep_time_minutes = ?
		WHERE id = ?
	`, data.Title, data.Description, data.Servings, data.PrepTimeMinutes, recipeID)
	return err
}

func (s *RecipeService) UpdateRecipeTags(tx sqlExecutor, recipeID int64, tags []string) error {
	_, err := tx.Exec(`
        DELETE FROM recipeTagsV1
        WHERE recipe_id = ?
    `, recipeID)

	if err != nil {
		return err
	}

	return s.SaveTags(tx, recipeID, tags)
}

func (s *RecipeService) InsertStepAndNotes(tx sqlExecutor, versionID int64, steps []Step) error {
	for _, step := range steps {
		_, err := tx.Exec(`
			INSERT INTO instructionsV1 (recipe_version_id, step_number, instruction, notes) VALUES (?, ?, ?, ?)
		`, versionID, step.StepNumber, step.Instruction, step.Notes)

		if err != nil {
			return fmt.Errorf("failed to insert steps: %w", err)
		}
	}

	return nil
}

func (s *RecipeService) InsertVersionIngredients(tx sqlExecutor, versionID int64, ingredients []Ingredient) error {

	for _, ingredient := range ingredients {
		_, err := tx.Exec(`
            INSERT INTO ingredientsV1 (recipe_version_id, name, quantity, unit) VALUES (?, ?, ?, ?)
        `, versionID, ingredient.Name, ingredient.Quantity, ingredient.Unit)

		if err != nil {
			return fmt.Errorf("failed to insert ingredient: %w", err)
		}
	}

	return nil
}

func (s *RecipeService) UpdateRecipe(userID int, recipeID int64, data RecipeUpdate) error {
	return withTx(s.DB, func(tx sqlExecutor) error {

		var exists int
		err := tx.QueryRow(`
			SELECT user_id
			FROM recipesV1
			WHERE id = ? AND user_id = ? 
		`, recipeID, userID).Scan(&exists)

		if errors.Is(err, sql.ErrNoRows) {
			return ErrRecipeNotFound
		}

		if err != nil {
			return fmt.Errorf("failed to verify recipe ownership: %w", err)
		}

		currentVersionID, err := s.GetLatestVersionID(
			tx, recipeID,
		)
		if err != nil {
			return err
		}

		currentIngredients, err := s.GetIngredients(tx, currentVersionID)
		if err != nil {
			return err
		}

		currentSteps, err := s.GetSteps(tx, currentVersionID)
		if err != nil {
			return err
		}

		data.Ingredients = mergeIngredients(data.Ingredients)

		ingredientsChanged := !ingredientsEqual(
			currentIngredients,
			data.Ingredients,
		)

		stepAndNotesChanged := !stepAndNotesEqual(
			currentSteps,
			data.Steps,
		)

		if ingredientsChanged || stepAndNotesChanged {

			newVersionID, err := s.NewVersion(
				tx, recipeID,
			)
			if err != nil {
				return err
			}

			// Save the edited ingredients
			if err := s.InsertVersionIngredients(tx, newVersionID, data.Ingredients); err != nil {
				return err
			}
			// Save the edited steps and notes
			if err := s.InsertStepAndNotes(tx, newVersionID, data.Steps); err != nil {
				return err
			}
		}

		if err := s.UpdateRecipeDetails(tx, recipeID, data); err != nil {
			return err
		}

		if err := s.UpdateRecipeTags(tx, recipeID, data.Tags); err != nil {
			return err
		}
		return nil
	})
}

// compares only what the user edits; IDs differ between versions.
func ingredientsEqual(old, updated []Ingredient) bool {
	return slices.EqualFunc(old, updated, func(a, b Ingredient) bool {
		return a.Name == b.Name && a.Quantity == b.Quantity && a.Unit == b.Unit
	})
}

func stepAndNotesEqual(old, updated []Step) bool {
	return slices.EqualFunc(old, updated, func(a, b Step) bool {
		return a.StepNumber == b.StepNumber && a.Instruction == b.Instruction && a.Notes == b.Notes
	})
}
