package services

import (
	"log"
	"strings"

	"github.com/jmoiron/sqlx"
)

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

type RecipeService struct {
	DB *sqlx.DB
}

var PresetTags = []string{
	"breakfast", "brunch", "lunch", "dinner", "dessert", "snack",
	"quick", "easy", "healthy", "comfort-food", "one-pot", "meal-prep",
	"vegetarian", "vegan", "gluten-free", "dairy-free", "low-carb",
	"italian", "mexican", "asian", "indian", "american", "mediterranean",
}

type PresetTagGroup struct {
	Name string
	Tags []string
}

var PresetTagGroups = []PresetTagGroup{
	{Name: "Meal type", Tags: []string{"breakfast", "brunch", "lunch", "dinner", "dessert", "snack"}},
	{Name: "Dietary", Tags: []string{"vegetarian", "vegan", "gluten-free", "dairy-free", "low-carb"}},
	{Name: "Preparation", Tags: []string{"quick", "easy", "healthy", "comfort-food", "one-pot", "meal-prep"}},
	{Name: "Cuisine", Tags: []string{"italian", "mexican", "asian", "indian", "american", "mediterranean"}},
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

func (s *RecipeService) SaveTags(recipeID int64, rawTags string) error {
	allowedTags := make(map[string]struct{}, len(PresetTags))
	for _, presetTag := range PresetTags {
		allowedTags[presetTag] = struct{}{}
	}
	seen := make(map[string]struct{})
	for _, rawTag := range strings.Split(rawTags, ",") {
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

		_, err := s.DB.Exec("INSERT INTO tagsV1(name) VALUES (?) ON CONFLICT(name) DO NOTHING", tag)
		if err != nil {
			return err
		}
		var tagID int64
		if err := s.DB.QueryRow("SELECT id FROM tagsV1 WHERE name = ?", tag).Scan(&tagID); err != nil {
			return err
		}
		if _, err := s.DB.Exec("INSERT OR IGNORE INTO recipeTagsV1(recipe_id, tag_id) VALUES (?, ?)", recipeID, tagID); err != nil {
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

func (s *RecipeService) NewVersion(recipeID int64) (int64, error) {
	var maxVersion int
	if err := s.DB.QueryRow(
		"SELECT COALESCE(MAX(version_number), 0) FROM recipe_versionsV1 WHERE recipe_id = ?",
		recipeID,
	).Scan(&maxVersion); err != nil {
		return 0, err
	}

	result, err := s.DB.Exec(
		"INSERT INTO recipe_versionsV1 (recipe_id, version_number) VALUES (?, ?)",
		recipeID, maxVersion+1,
	)
	if err != nil {
		return 0, err
	}
	return result.LastInsertId()
}

func (s *RecipeService) GetRecipeForEdit(recipeID int64) (*RecipeEditPageData, error) {
	var title string
	row := s.DB.QueryRow("SELECT title FROM recipesV1 WHERE id = ?", recipeID)
	if err := row.Scan(&title); err != nil {
		return nil, err
	}

	var versionID int64
	row = s.DB.QueryRow(
		"SELECT id FROM recipe_versionsV1 WHERE recipe_id = ? ORDER BY version_number DESC LIMIT 1",
		recipeID,
	)
	if err := row.Scan(&versionID); err != nil {
		return nil, err
	}

	ingredients, err := s.GetIngredients(versionID)
	if err != nil {
		return nil, err
	}

	steps, err := s.GetSteps(versionID)
	if err != nil {
		return nil, err
	}

	return &RecipeEditPageData{
		Recipe: RecipeInfo{
			ID:        recipeID,
			VersionID: versionID,
			Title:     title,
		},
		Ingredients: ingredients,
		Steps:       steps,
	}, nil
}

func (s *RecipeService) GetIngredients(recipeVersionID int64) ([]Ingredient, error) {
	var ingredients []Ingredient
	rows, err := s.DB.Query(
		"SELECT id, recipe_version_id, name, quantity, unit FROM ingredientsV1 WHERE recipe_version_id = ?", recipeVersionID,
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

	for rows.Next() {
		var i Ingredient
		if err := rows.Scan(&i.ID, &i.RecipeVersionID, &i.Name, &i.Quantity, &i.Unit); err != nil {
			return nil, err
		}
		ingredients = append(ingredients, i)
	}
	return ingredients, nil
}

func (s *RecipeService) GetSteps(recipeVersionID int64) ([]Step, error) {
	var steps []Step
	rows, err := s.DB.Query(
		"SELECT id, recipe_version_id, step_number, instruction, COALESCE(notes, '') FROM instructionsV1 WHERE recipe_version_id = ? ORDER BY step_number", recipeVersionID,
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

	for rows.Next() {
		var st Step
		if err := rows.Scan(&st.ID, &st.RecipeVersionID, &st.StepNumber, &st.Instruction, &st.Notes); err != nil {
			return nil, err
		}
		steps = append(steps, st)
	}
	return steps, nil
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
            0 AS version_id,
            COALESCE(r.description, '') AS description,
            COALESCE(r.image_url, '') AS image_url
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
		// if err := rows.Scan(&ri.ID, &ri.Title, &ri.VersionID); err != nil {
		// 	return nil, err
		// }
		if err := rows.Scan(&ri.ID, &ri.Title, &ri.VersionID, &ri.Description, &ri.ImageURL); err != nil {
			return nil, err
		}
		recipes = append(recipes, ri)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return recipes, nil
}

func (s *RecipeService) GetLatestVersionID(recipeID int64) (int64, error) {
	var versionID int64
	err := s.DB.QueryRow(
		"SELECT id FROM recipe_versionsV1 WHERE recipe_id = ? ORDER BY version_number DESC LIMIT 1",
		recipeID,
	).Scan(&versionID)
	if err != nil {
		return 0, err
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

	searchQuery := `SELECT r.id, r.title, COALESCE(r.description, ''), COALESCE(r.image_url, ''),
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
		if err := rows.Scan(&ri.ID, &ri.Title, &ri.Description, &ri.ImageURL, &tags); err != nil {
			return nil, err
		}
		ri.Tags = splitTags(tags)

		recipes = append(recipes, ri)
	}

	return recipes, nil
}

func (s *RecipeService) GetAllRecipes() ([]RecipeInfo, error) {
	rows, err := s.DB.Query(
		`SELECT r.id, r.title, COALESCE(r.description, ''), COALESCE(r.image_url, ''),
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
		if err := rows.Scan(&ri.ID, &ri.Title, &ri.Description, &ri.ImageURL, &tags); err != nil {
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

	var versionID int64
	err = s.DB.QueryRow(
		"SELECT id FROM recipe_versionsV1 WHERE recipe_id = ? ORDER BY version_number DESC LIMIT 1",
		recipeID,
	).Scan(&versionID)
	if err != nil {
		return nil, 0, err
	}

	ingredients, err := s.GetIngredients(versionID)
	if err != nil {
		return nil, 0, err
	}

	steps, err := s.GetSteps(versionID)
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
