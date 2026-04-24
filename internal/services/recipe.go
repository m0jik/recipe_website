package services

import (
	"github.com/jmoiron/sqlx"
)

type RecipeInfo struct {
	ID          int64 // recipe ID
	VersionID   int64 // current version ID
	Title       string
	Description string
	ImageURL    string
	UserID      int64
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

func NewRecipeService(db *sqlx.DB) *RecipeService {
	return &RecipeService{DB: db}
}

func (s *RecipeService) CreateRecipe(userID int, title, imageURL string, description string) (int64, error) {
	result, err := s.DB.Exec(
		"INSERT INTO recipesV1(user_id, title, image_url, description) VALUES (?, ?, ?, ?)",
		userID,
		title,
		imageURL,
		description,
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
	defer rows.Close()
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
	defer rows.Close()
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
		`SELECT r.id, r.title, COALESCE(rv.id, 0)
		 FROM recipesV1 r
		 LEFT JOIN recipe_versionsV1 rv ON rv.recipe_id = r.id
		   AND rv.version_number = (SELECT MAX(version_number) FROM recipe_versionsV1 WHERE recipe_id = r.id)
		 WHERE r.user_id = ?
		 ORDER BY r.created_at DESC`,
		userID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var recipes []RecipeInfo
	for rows.Next() {
		var ri RecipeInfo
		if err := rows.Scan(&ri.ID, &ri.Title, &ri.VersionID); err != nil {
			return nil, err
		}
		recipes = append(recipes, ri)
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

func (r *RecipeService) Search(query string) ([]RecipeInfo, error) {
	rows, err := r.DB.Query(
		`SELECT id, title, COALESCE(description, ''), COALESCE(image_url, '') FROM recipesV1 WHERE title LIKE ? OR description LIKE ? ORDER BY created_at DESC`,
		"%"+query+"%",
		"%"+query+"%",
	)

	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var recipes []RecipeInfo

	for rows.Next() {
		var ri RecipeInfo
		if err := rows.Scan(&ri.ID, &ri.Title, &ri.Description, &ri.ImageURL); err != nil {
			return nil, err
		}

		recipes = append(recipes, ri)
	}

	return recipes, nil
}

func (r *RecipeService) GetAllRecipes() ([]RecipeInfo, error) {
	rows, err := r.DB.Query(
		`SELECT id, title, COALESCE(description, ''), COALESCE(image_url, '') FROM recipesV1 ORDER BY created_at DESC`,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var recipes []RecipeInfo

	for rows.Next() {
		var ri RecipeInfo
		if err := rows.Scan(&ri.ID, &ri.Title, &ri.Description, &ri.ImageURL); err != nil {
			return nil, err
		}
		recipes = append(recipes, ri)
	}

	return recipes, nil
}

func (r *RecipeService) GetRecipeForView(recipeID int64) (*RecipeEditPageData, int64, error) {
	var title string
	var userID int64
	var description string
	var imageURL string

	err := r.DB.QueryRow(
		"SELECT title, user_id, COALESCE(description, ''), COALESCE(image_url, '') FROM recipesV1 WHERE id = ?",
		recipeID,
	).Scan(&title, &userID, &description, &imageURL)

	if err != nil {
		return nil, 0, err
	}

	var versionID int64
	err = r.DB.QueryRow(
		"SELECT id FROM recipe_versionsV1 WHERE recipe_id = ? ORDER BY version_number DESC LIMIT 1",
		recipeID,
	).Scan(&versionID)

	if err != nil {
		return nil, 0, err
	}

	ingredients, err := r.GetIngredients(versionID)
	if err != nil {
		return nil, 0, err
	}

	steps, err := r.GetSteps(versionID)
	if err != nil {
		return nil, 0, err
	}

	return &RecipeEditPageData{
		Recipe: RecipeInfo{
			ID:          recipeID,
			VersionID:   versionID,
			Title:       title,
			Description: description,
			ImageURL:    imageURL,
		},
		Ingredients: ingredients,
		Steps:       steps,
	}, userID, nil
}
