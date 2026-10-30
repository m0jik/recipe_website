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

type RecipeV1 struct {
	PrimaryName     string
	VariantName     string
	VersionID       int64
	Description     string
	ImageURL        string
	CreatorID       string
	Servings        int
	PrepTimeMinutes time.Duration
	Tags            []string
	Steps           []RecipeStepV1
}

type IngredientV1 struct {
	Name    string
	Aliases []string
	Amount  string
	Unit    string
}

type RecipeStepV1 struct {
	Instruction     string
	StepIngredients []RecipeStepIngredientV1
}

type RecipeStepIngredientV1 struct {
	RecipeID int64
	StepID   int64
	Name     string
	Aliases  []string
	Amount   string
	Unit     string
}

type RecipeVersionV1 struct {
	RecipeID      int64
	VersionNumber int
	CreatedAt     time.Time
}

type RecipeUpdateV1 struct {
	Title           string
	ImageURL        string
	Description     string
	Tags            []string
	Servings        int
	PrepTimeMinutes int
	Ingredients     []IngredientV1
	Steps           []RecipeStepV1
}

type RecipeEditPageData struct {
	Recipe          RecipeV1
	Ingredients     []IngredientV1
	Steps           []RecipeStepV1
	StepIngredients []RecipeStepIngredientV1
}

type RecipeServiceV1 struct {
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

func NewRecipeService(db *sqlx.DB) *RecipeServiceV1 {
	return &RecipeServiceV1{DB: db}
}

func (s *RecipeServiceV1) CreateRecipe(userID int, title, imageURL string, primaryName, variantName, creatorID, description string, servings int, prepTimeMinutes int) error {
	_, err := s.DB.Exec(
		"INSERT INTO recipesV1(user_id, title, image_url, description, servings, prep_time_minutes) VALUES (?, ?, ?, ?, ?, ?)",
		userID,
		title,
		imageURL,
		description,
		servings,
		prepTimeMinutes,
	)
	if err != nil {
		return err
	}

	_, err = s.DB.Exec( // creates the first version
		`INSERT INTO recipe_versionsV1 (recipe_id, version_number)
         VALUES (?, 1)`,
		primaryName, variantName, creatorID,
	)
	if err != nil {
		return err
	}
	return nil
}

func (s *RecipeServiceV1) SaveTags(tx sqlExecutor, primaryName, variantName, creatorID string, tags []string) error {
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
			primaryName, variantName, creatorID, tagID,
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

func (s *RecipeServiceV1) BatchSaveIngredients(versionID int64, names, quantities, units []string) error {
	for i, name := range names {
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		qty := ""
		if i < len(quantities) {
			qty = strings.TrimSpace(quantities[i])
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

func (s *RecipeServiceV1) BatchSaveSteps(versionID int64, instructions, notes, step_ingredients []string) error {
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
		for _, step_ingredient := range strings.Split(strings.Trim(step_ingredients[i], "[] "), "  ") {
			step_ingredient = strings.TrimSpace(step_ingredient)
			if step_ingredient == "" {
				continue
			}
			_, err := s.DB.Exec(
				"INSERT INTO step_ingredientsV1 (recipe_id, step_id, step_ingredient) VALUES (?, ?, ?)",
				versionID, i+1, step_ingredient,
			)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

func (s *RecipeServiceV1) NewVersion(tx sqlExecutor, primaryName, variantName, creatorID string) (int64, error) {
	var maxVersion int
	if err := tx.QueryRow(
		"SELECT COALESCE(MAX(version_number), 0) FROM recipe_versionsV1 WHERE recipe_id = ?",
		primaryName, variantName, creatorID,
	).Scan(&maxVersion); err != nil {
		return 0, err
	}

	result, err := tx.Exec(
		"INSERT INTO recipe_versionsV1 (recipe_id, version_number) VALUES (?, ?)",
		primaryName, variantName, creatorID, maxVersion+1,
	)
	if err != nil {
		return 0, err
	}
	return result.LastInsertId()
}

func (s *RecipeServiceV1) GetIngredients(q sqlExecutor, recipeVersionID int64) ([]IngredientV1, error) {
	var ingredients []IngredientV1
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
		var i IngredientV1
		if err := rows.Scan(&i.Name, &i.Aliases, &i.Amount, &i.Unit); err != nil {
			return nil, err
		}
		ingredients = append(ingredients, i)
	}
	return ingredients, rows.Err()
}

func (s *RecipeServiceV1) GetSteps(tx sqlExecutor, recipeVersionID int64) ([]RecipeStepV1, error) {
	var steps []RecipeStepV1
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
		var st RecipeStepV1
		if err := rows.Scan(&st.Instruction, &st.StepIngredients); err != nil {
			return nil, err
		}
		steps = append(steps, st)
	}

	StepIngredients, err := s.GetStepIngredients(recipeVersionID)
	if err != nil {
		return nil, err
	}
	for i := range steps {
		for _, si := range StepIngredients {
			steps[i].StepIngredients = append(steps[i].StepIngredients, si)
		}
	}
	return steps, rows.Err()
}

// GetVersions returns every version of a recipe, newest first.
func (s *RecipeServiceV1) GetVersions(recipeID int64) ([]RecipeVersionV1, error) {
	var versions []RecipeVersionV1
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
		var v RecipeVersionV1
		if err := rows.Scan(&v.RecipeID, &v.VersionNumber, &v.CreatedAt); err != nil {
			return nil, err
		}
		versions = append(versions, v)
	}
	return versions, rows.Err()
}

// GetVersion returns one version of a recipe, only if the recipe belongs to userID.
func (s *RecipeServiceV1) GetVersion(userID int, recipeID int64, versionID int64) (RecipeVersionV1, error) {
	var v RecipeVersionV1
	err := s.DB.QueryRow(`
		SELECT rv.id, rv.version_number, rv.created_at
		FROM recipe_versionsV1 rv
		JOIN recipesV1 r ON r.id = rv.recipe_id
		WHERE rv.id = ? AND rv.recipe_id = ? AND r.user_id = ?
	`, versionID, recipeID, userID).Scan(&v.RecipeID, &v.VersionNumber, &v.CreatedAt)

	if errors.Is(err, sql.ErrNoRows) {
		return v, ErrRecipeNotFound
	}
	return v, err
}

func (s *RecipeServiceV1) GetStepIngredients(recipeVersionID int64) ([]RecipeStepIngredientV1, error) {
	var stepIngredients []RecipeStepIngredientV1
	rows, err := s.DB.Query(
		`SELECT id, recipe_id, step_id, step_ingredient
		 FROM step_ingredientsV1
		 WHERE recipe_id = ?
		`, recipeVersionID,
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
		var si RecipeStepIngredientV1
		if err := rows.Scan(&si.RecipeID, &si.StepID, &si.Name, &si.Aliases, &si.Amount, &si.Unit); err != nil {
			return nil, err
		}
		stepIngredients = append(stepIngredients, si)
	}
	return stepIngredients, rows.Err()
}

func (s *RecipeServiceV1) GetRecipesByUser(userID int) ([]RecipeV1, error) {
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

	var recipes []RecipeV1
	for rows.Next() {
		var r RecipeV1
		var tags string
		// if err := rows.Scan(&ri.ID, &ri.Title, &ri.VersionID); err != nil {
		// 	return nil, err
		// }
		if err := rows.Scan(&r.PrimaryName, &r.VariantName, &r.CreatorID, &r.Description, &r.ImageURL, &tags); err != nil {
			return nil, err
		}
		r.Tags = splitTags(tags)
		recipes = append(recipes, r)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return recipes, nil
}

func (s *RecipeServiceV1) GetLatestVersionID(tx sqlExecutor, primaryName, variantName, creatorID string) (int64, error) {

	var versionID int64

	err := tx.QueryRow(` //TODO: More database fixes
        SELECT id
        FROM recipe_versionsV1
        WHERE recipe_id = ?
        ORDER BY version_number DESC
        LIMIT 1
    `, primaryName, variantName, creatorID).Scan(&versionID)

	if err != nil {
		return 0, fmt.Errorf(
			"failed to get latest version: %w", err,
		)
	}

	return versionID, nil
}

func (s *RecipeServiceV1) GetRecipeUser(recipeID int64) (int64, error) {
	var userID int64
	err := s.DB.QueryRow(
		"SELECT user_id FROM recipesV1 WHERE id = ?",
		recipeID,
	).Scan(&userID)

	if errors.Is(err, sql.ErrNoRows) {
		return 0, ErrRecipeNotFound
	}
	return userID, err
}

func (s *RecipeServiceV1) Search(query string, tagFilters []string, maxTime int) ([]RecipeV1, error) {
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

	if err := rows.Err(); err != nil {
		log.Println("Error iterating over rows:", err)
	}

	// defer rows.Close()
	defer func() {
		if err := rows.Close(); err != nil {
			log.Println("Error closing rows:", err)
		}
	}()

	var recipes []RecipeV1

	for rows.Next() {
		var r RecipeV1
		var tags string
		if err := rows.Scan(&r.PrimaryName, &r.VariantName, &r.CreatorID, &r.Description, &r.ImageURL, &tags); err != nil {
			return nil, err
		}
		r.Tags = splitTags(tags)

		recipes = append(recipes, r)
	}

	return recipes, nil
}

func (s *RecipeServiceV1) GetAllRecipes() ([]RecipeV1, error) {
	rows, err := s.DB.Query(
		`SELECT r.id, r.user_id, r.title, COALESCE(r.description, ''), COALESCE(r.image_url, ''),
			COALESCE((SELECT GROUP_CONCAT(t.name, ',') FROM tagsV1 t JOIN recipeTagsV1 rt ON rt.tag_id = t.id WHERE rt.recipe_id = r.id), '')
		 FROM recipesV1 r ORDER BY r.created_at DESC`,
	)
	if err != nil {
		return nil, err
	}

	if err := rows.Err(); err != nil {
		log.Println("Error iterating over rows:", err)
	}

	// defer rows.Close()
	defer func() {
		if err := rows.Close(); err != nil {
			log.Println("Error closing rows:", err)
		}
	}()

	var recipes []RecipeV1

	for rows.Next() {
		var ri RecipeV1
		var tags string
		if err := rows.Scan(&ri.PrimaryName, &ri.VariantName, &ri.CreatorID, &ri.Description, &ri.ImageURL, &tags); err != nil {
			return nil, err
		}
		ri.Tags = splitTags(tags)
		recipes = append(recipes, ri)
	}

	return recipes, nil
}

func (s *RecipeServiceV1) GetRecipeForView(primaryName, variantName, creatorID string) (*RecipeEditPageData, string, error) {
	var description string
	var imageURL string
	var servings int
	var prepTime time.Duration

	err := s.DB.QueryRow(
		"SELECT title, user_id, COALESCE(description, ''), COALESCE(image_url, ''), COALESCE(servings, 0), COALESCE(prep_time_minutes, 0) FROM recipesV1 WHERE id = ?",
		primaryName, variantName, creatorID, //TODO: Fix this database call and put it into its own service to interface into
	).Scan(&primaryName, &variantName, &creatorID, &description, &imageURL, &servings, &prepTime)
	if err != nil {
		return nil, "", err
	}

	versionID, err := s.GetLatestVersionID(s.DB, primaryName, variantName, creatorID)
	if err != nil {
		return nil, "", err
	}

	ingredients, err := s.GetIngredients(s.DB, versionID)
	if err != nil {
		return nil, "", err
	}

	steps, err := s.GetSteps(s.DB, versionID)
	if err != nil {
		return nil, "", err
	}

	stepIngredients, err := s.GetStepIngredients(versionID)
	if err != nil {
		return nil, "", err
	}

	var tagString string
	if err := s.DB.QueryRow( //TODO: Fix this database call and put it into its own service to interface into
		`SELECT COALESCE(GROUP_CONCAT(t.name, ','), '') FROM tagsV1 t
		 JOIN recipeTagsV1 rt ON rt.tag_id = t.id WHERE rt.recipe_id = ?`, primaryName, variantName, creatorID,
	).Scan(&tagString); err != nil {
		return nil, "", err
	}

	return &RecipeEditPageData{
		Recipe: RecipeV1{
			PrimaryName:     primaryName,
			VariantName:     variantName,
			VersionID:       versionID,
			Description:     description,
			ImageURL:        imageURL,
			Servings:        servings,
			PrepTimeMinutes: prepTime,
			Tags:            splitTags(tagString),
		},
		Ingredients:     ingredients,
		Steps:           steps,
		StepIngredients: stepIngredients,
	}, creatorID, nil
}

func (s *RecipeServiceV1) DeleteRecipe(recipeID int64) error {
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
			DELETE FROM step_ingredientsV1
			WHERE recipe_id IN (
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

func (s *RecipeServiceV1) UpdateRecipeDetails(tx sqlExecutor, primaryName, variantName, creatorID string, data RecipeUpdateV1) error {
	_, err := tx.Exec(`
		UPDATE recipesV1
		SET title = ?, description = ?, image_url = COALESCE(NULLIF(?, ''), image_url), servings = ?, prep_time_minutes = ?
		WHERE id = ?
	`, data.Title, data.Description, data.ImageURL, data.Servings, data.PrepTimeMinutes, primaryName, variantName, creatorID)
	return err
}

func (s *RecipeServiceV1) UpdateRecipeTags(tx sqlExecutor, primaryName, variantName, creatorID string, tags []string) error {
	_, err := tx.Exec(`
        DELETE FROM recipeTagsV1
        WHERE recipe_id = ?
    `, primaryName, variantName, creatorID)

	if err != nil {
		return err
	}

	return s.SaveTags(tx, primaryName, variantName, creatorID, tags)
}

func (s *RecipeServiceV1) InsertStepAndNotes(tx sqlExecutor, primaryName, variantName, creatorID string, steps []RecipeStepV1) error {
	for _, step := range steps { //TODO: More database stuff.
		_, err := tx.Exec(` 
			INSERT INTO instructionsV1 (recipe_version_id, step_number, instruction, notes) VALUES (?, ?, ?, ?)
		`, primaryName, variantName, creatorID, step.Instruction)

		if err != nil {
			return fmt.Errorf("failed to insert steps: %w", err)
		}

		for _, si := range step.StepIngredients {
			_, err := tx.Exec(`
				INSERT INTO step_ingredientsV1 (recipe_id, step_id, step_ingredient) VALUES (?, ?, ?)
			`, primaryName, variantName, creatorID, si.Name, si.Aliases, si.Amount, si.Unit)

			if err != nil {
				return fmt.Errorf("failed to insert step ingredients: %w", err)
			}
		}
	}

	return nil
}

func (s *RecipeServiceV1) InsertVersionIngredients(tx sqlExecutor, primaryName, variantName, creatorID string, ingredients []IngredientV1) error {

	for _, ing := range ingredients {
		_, err := tx.Exec(`
            INSERT INTO ingredientsV1 (recipe_version_id, name, quantity, unit) VALUES (?, ?, ?, ?)
        `, primaryName, variantName, creatorID, ing.Name, ing.Amount, ing.Unit)

		if err != nil {
			return fmt.Errorf("failed to insert ingredient: %w", err)
		}
	}

	return nil
}

func (s *RecipeServiceV1) UpdateRecipe(userID int, primaryName, variantName, creatorID string, data RecipeUpdateV1) error {
	return withTx(s.DB, func(tx sqlExecutor) error {

		var exists int

		//TODO: More database stuff.
		err := tx.QueryRow(`
			SELECT user_id
			FROM recipesV1
			WHERE id = ? AND user_id = ? 
		`, primaryName, variantName, creatorID, userID).Scan(&exists)

		if errors.Is(err, sql.ErrNoRows) {
			return ErrRecipeNotFound
		}

		if err != nil {
			return fmt.Errorf("failed to verify recipe ownership: %w", err)
		}

		currentVersionID, err := s.GetLatestVersionID(
			tx, primaryName, variantName, creatorID,
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

		ingredientsChanged := !ingredientsEqual(currentIngredients, data.Ingredients)

		stepsChanged := !stepsEqual(
			currentSteps,
			data.Steps,
		)

		// Any change to ingredients, steps, notes or step ingredients makes a new version.
		if ingredientsChanged || stepsChanged {

			// Save the edited ingredients
			if err := s.InsertVersionIngredients(tx, primaryName, variantName, creatorID, data.Ingredients); err != nil {
				return err
			}
			// Save the edited steps and notes
			if err := s.InsertStepAndNotes(tx, primaryName, variantName, creatorID, data.Steps); err != nil {
				return err
			}
		}

		if err := s.UpdateRecipeDetails(tx, primaryName, variantName, creatorID, data); err != nil {
			return err
		}

		if err := s.UpdateRecipeTags(tx, primaryName, variantName, creatorID, data.Tags); err != nil {
			return err
		}
		return nil
	})
}

// compares only what the user edits; IDs differ between versions.
func ingredientsEqual(old, updated []IngredientV1) bool {
	return slices.EqualFunc(old, updated, func(a, b IngredientV1) bool {
		return a.Name == b.Name && slices.Equal(a.Aliases, b.Aliases) && a.Amount == b.Amount && a.Unit == b.Unit
	})
}

func stepsEqual(old, updated []RecipeStepV1) bool {
	return slices.EqualFunc(old, updated, func(a, b RecipeStepV1) bool {
		return a.Instruction == b.Instruction &&
			slices.EqualFunc(a.StepIngredients, b.StepIngredients, func(x, y RecipeStepIngredientV1) bool {
				return x.Name == y.Name && slices.Equal(x.Aliases, y.Aliases) && x.Amount == y.Amount && x.Unit == y.Unit
			})
	})
}

func (s *RecipeServiceV1) GetCookBookRecipes(userID int) ([]RecipeV1, error) {
	rows, err := s.DB.Query(`
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

	if err != nil {
		return nil, err
	}

	defer func() {
		if err := rows.Close(); err != nil {
			log.Println("Error closing rows:", err)
		}
	}()

	var recipes []RecipeV1

	for rows.Next() {
		var r RecipeV1
		var tags string
		if err := rows.Scan(&r.PrimaryName, &r.VariantName, &r.CreatorID, &r.Description, &r.ImageURL, &tags, &r.Servings, &r.PrepTimeMinutes); err != nil {
			return nil, err
		}
		r.Tags = splitTags(tags)
		recipes = append(recipes, r)
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}

	return recipes, nil
}
