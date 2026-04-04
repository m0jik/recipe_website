package services

import (
	"github.com/jmoiron/sqlx"
)

type RecipeInfo struct {
	ID        int64 // recipe ID
	VersionID int64 // current version ID
	Title     string
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
	Quantity        float64
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

func (s *RecipeService) AddIngredient(recipeVersionID int64, name string, quantity float64, unit string) error {
	_, err := s.DB.Exec(
		"INSERT INTO ingredientsV1 (recipe_version_id, name, quantity, unit) VALUES (?, ?, ?, ?)",
		recipeVersionID,
		name,
		quantity,
		unit,
	)
	return err
}

func (s *RecipeService) AddInstruction(recipeVersionID int64, instruction string, notes string) error {
	var maxStep int
	if err := s.DB.QueryRow(
		"SELECT COALESCE(MAX(step_number), 0) FROM instructionsV1 WHERE recipe_version_id = ?",
		recipeVersionID,
	).Scan(&maxStep); err != nil {
		return err
	}

	_, err := s.DB.Exec(
		"INSERT INTO instructionsV1 (recipe_version_id, step_number, instruction, notes) VALUES (?, ?, ?, ?)",
		recipeVersionID,
		maxStep+1,
		instruction,
		notes,
	)
	return err
}

// u;sed for going back to form 1
func (s *RecipeService) GetRecipeDetails(recipeID int64) (title, imageURL, description string, err error) {
	err = s.DB.QueryRow(
		"SELECT title, COALESCE(image_url,''), COALESCE(description,'') FROM recipesV1 WHERE id = ?", recipeID,
	).Scan(&title, &imageURL, &description)
	return
}

// used for creating a recipe form 1
func (s *RecipeService) UpdateRecipe(recipeID int64, title, imageURL, description string) error {
	_, err := s.DB.Exec(
		"UPDATE recipesV1 SET title = ?, image_url = ?, description = ? WHERE id = ?",
		title, imageURL, description, recipeID,
	)
	return err
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

func (s *RecipeService) DeleteIngredient(recipeVersionID, ingredientID int64) error {
	_, err := s.DB.Exec(
		"DELETE FROM ingredientsV1 WHERE id = ? AND recipe_version_id = ?",
		ingredientID, recipeVersionID,
	)
	return err
}

// Can wait
// func(s *RecipeService) DeleteInstruction() {

// }

// func (s *RecipeService) DeleteIngredient() {

// }

// func (s *RecipeService) GetLatestVersion() {

// }

// NEeded
// func (s *RecipeService) EditInstruction() {

// }

// func (s *RecipeService) GetRecipeByID() {

// }

// }

// func (s *RecipeService) PublishRecipe() {

// }

// Versioning when making changes
// func (s *RecipeService) CopyVersionIngredients {

// }

// func (s *RecipeService)CopyVersionInstructions {
// }

// RevertVersion
