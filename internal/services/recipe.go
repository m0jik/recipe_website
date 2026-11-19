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
	CreatedAt       time.Time
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
	Name    string
	Aliases []string
	Amount  string
	Unit    string
}

type RecipeVersionV1 struct {
	PrimaryName   string
	VariantName   string
	CreatorID     string
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

func (s *RecipeServiceV1) CreateRecipe(imageURL, primaryName, variantName, creatorID, description string, servings, prepTimeMinutes int) error {

	_, err := InsertRecipeIntoRecipesTable(s, imageURL, primaryName, variantName, creatorID, description, servings, prepTimeMinutes)
	if err != nil {
		return err
	}

	_, err = InsertRecipeIntoRecipeVersionsTable(s, primaryName, variantName, creatorID)
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

		_, err := InsertTagsIntoTagsTable(tx, tag)
		if err != nil {
			return err
		}

		var tagName string
		if err := GetTagFromTagsTable(tx, tag).Scan(&tagName); err != nil {
			return err
		}

		if _, err := InsertRecipeIntoRecipeTagsTable(tx, primaryName, variantName, creatorID, tagName); err != nil {
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

func (s *RecipeServiceV1) BatchSaveIngredients(versionID int64, names, quantities, units []string, primaryName, variantName, creatorID string) error {
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
		_, err := InsertIntoIngredientsTable(s, versionID, name, qty, unit, primaryName, variantName, creatorID)
		if err != nil {
			return err
		}
	}
	return nil
}

func (s *RecipeServiceV1) BatchSaveSteps(versionID int64, instructions, notes, step_ingredients []string, primaryName, variantName, creatorID string) error {
	for i, instruction := range instructions {
		if instruction == "" {
			continue
		}
		_, err := InsertIntoInstructionsTable(s, versionID, i, instruction, primaryName, variantName, creatorID)
		if err != nil {
			return err
		}
		for _, step_ingredient := range strings.Split(strings.Trim(step_ingredients[i], "[] "), "  ") {
			step_ingredient = strings.TrimSpace(step_ingredient)
			if step_ingredient == "" {
				continue
			}
			_, err := InsertIntoStepIngredientsTable(s, versionID, i, step_ingredient)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

func (s *RecipeServiceV1) NewVersion(tx sqlExecutor, primaryName, variantName, creatorID string) (int64, error) {
	var maxVersion int
	if err := GetLargestVersionNumber(tx, primaryName, variantName, creatorID).Scan(&maxVersion); err != nil {
		return 0, err
	}

	result, err := InsertNewRecipeVersionIntoRecipeVersionTable(tx, primaryName, variantName, creatorID, maxVersion)
	if err != nil {
		return 0, err
	}
	return result.LastInsertId()
}

func (s *RecipeServiceV1) GetIngredients(q sqlExecutor, primaryName, variantName, creatorID string) ([]IngredientV1, error) {
	var ingredients []IngredientV1
	rows, err := GetIngredientsFromIngredientsTable(q, primaryName, variantName, creatorID)
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
		if err := rows.Scan(&i.Name, &i.Amount, &i.Unit); err != nil {
			return nil, err
		}
		ingredients = append(ingredients, i)
	}
	return ingredients, rows.Err()
}

func (s *RecipeServiceV1) GetSteps(tx sqlExecutor, primaryName, variantName, creatorID string) ([]RecipeStepV1, error) {
	var steps []RecipeStepV1
	rows, err := GetStepsFromInstructionsTable(tx, primaryName, variantName, creatorID)
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

	StepIngredients, err := s.GetStepIngredients(primaryName, variantName, creatorID)
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
func (s *RecipeServiceV1) GetVersions(primaryName, variantName, creatorID string) ([]RecipeVersionV1, error) {
	var versions []RecipeVersionV1
	rows, err := GetVersionsFromRecipeVersionsTable(s, primaryName, variantName, creatorID)
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
		if err := rows.Scan(primaryName, variantName, creatorID, &v.VersionNumber, &v.CreatedAt); err != nil {
			return nil, err
		}
		versions = append(versions, v)
	}
	return versions, rows.Err()
}

// GetVersion returns one version of a recipe, only if the recipe belongs to userID.
func (s *RecipeServiceV1) GetVersion(userID, primaryName, variantName, creatorID string, versionID int64) (RecipeVersionV1, error) {
	var v RecipeVersionV1
	err := GetVersionBelongingToUserID(s, versionID, primaryName, variantName, creatorID, userID).Scan(primaryName, variantName, creatorID, &v.VersionNumber, &v.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return v, ErrRecipeNotFound
	}
	return v, err
}

func (s *RecipeServiceV1) GetStepIngredients(primaryName, variantName, creatorID string) ([]RecipeStepIngredientV1, error) {
	var stepIngredients []RecipeStepIngredientV1
	rows, err := GetStepIngredientsFromStepIngredientsTable(s, primaryName, variantName, creatorID)
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
		if err := rows.Scan(primaryName, variantName, creatorID, &si.Name, &si.Aliases, &si.Amount, &si.Unit); err != nil {
			return nil, err
		}
		stepIngredients = append(stepIngredients, si)
	}
	return stepIngredients, rows.Err()
}

func (s *RecipeServiceV1) GetRecipesByUser(userID string) ([]RecipeV1, error) {
	rows, err := GetRecipesByUserID(s, userID)
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
		if err := rows.Scan(&r.PrimaryName, &r.VariantName, &r.CreatorID, &r.VersionID, &r.Description, &r.ImageURL, &tags); err != nil {
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

	err := GetLatestVersionIDFromRecipeVersionsTable(tx, primaryName, variantName, creatorID).Scan(&versionID)

	if err != nil {
		return 0, fmt.Errorf(
			"failed to get latest version: %w", err,
		)
	}

	return versionID, nil
}

func (s *RecipeServiceV1) GetRecipeUser(recipeID int64) (int64, error) {
	var userID int64
	err := GetUserFromRecipesTable(s, recipeID).Scan(&userID)

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
		conditions = SearchByTag(conditions)
		args = append(args, tag)
	}
	if maxTime > 0 {
		conditions = append(conditions, "r.prep_time_minutes IS NOT NULL AND r.prep_time_minutes <= ?")
		args = append(args, maxTime)
	}

	conditions = SearchByTitleAndDescription(conditions)

	rows, err := CallSearchQuery(s, args, conditions, query)
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
	rows, err := GetAllRecipesFromRecipesTable(s)
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

	err := GetRecipeFromRecipeTable(s, primaryName, variantName, creatorID).Scan(&primaryName, &variantName, &creatorID, &description, &imageURL, &servings, &prepTime)
	if err != nil {
		return nil, "", err
	}

	versionID, err := s.GetLatestVersionID(s.DB, primaryName, variantName, creatorID)
	if err != nil {
		return nil, "", err
	}

	ingredients, err := s.GetIngredients(s.DB, primaryName, variantName, creatorID)
	if err != nil {
		return nil, "", err
	}

	steps, err := s.GetSteps(s.DB, primaryName, variantName, creatorID)
	if err != nil {
		return nil, "", err
	}

	stepIngredients, err := s.GetStepIngredients(primaryName, variantName, creatorID)
	if err != nil {
		return nil, "", err
	}

	var tagString string
	if err := GetTagString(s, primaryName, variantName, creatorID).Scan(&tagString); err != nil {
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

func (s *RecipeServiceV1) DeleteRecipe(primaryName, variantName, creatorID string) error {
	return withTx(s.DB, func(tx sqlExecutor) error {

		if _, err := DeleteFromUserShoppingListTable(tx, primaryName, variantName, creatorID); err != nil {
			return err
		}

		if _, err := DeleteFromUserShoppingStateTable(tx); err != nil {
			return err
		}

		if _, err := DeleteFromIngredientsTable(tx, primaryName, variantName, creatorID); err != nil {
			return err
		}

		if _, err := DeleteFromStepIngredientsTable(tx, primaryName, variantName, creatorID); err != nil {
			return err
		}

		if _, err := DeleteFromInstructionsTable(tx, primaryName, variantName, creatorID); err != nil {
			return err
		}

		if _, err := DeleteFromRecipeVersionsTable(tx, primaryName, variantName, creatorID); err != nil {
			return err
		}

		if _, err := DeleteFromRecipeTagsTable(tx, primaryName, variantName, creatorID); err != nil {
			return err
		}

		if _, err := DeleteFromRecipesTable(tx, primaryName, variantName, creatorID); err != nil {
			return err
		}

		return nil
	})
}

func (s *RecipeServiceV1) UpdateRecipeDetails(tx sqlExecutor, primaryName, variantName, creatorID string, data RecipeUpdateV1) error {
	_, err := UpdateRecipeDetailsToRecipeTable(tx, data, primaryName, variantName, creatorID)
	return err
}

func (s *RecipeServiceV1) UpdateRecipeTags(tx sqlExecutor, primaryName, variantName, creatorID string, tags []string) error {
	_, err := DeleteFromRecipeTagsTable(tx, primaryName, variantName, creatorID)

	if err != nil {
		return err
	}

	return s.SaveTags(tx, primaryName, variantName, creatorID, tags)
}

func (s *RecipeServiceV1) InsertStepAndNotes(tx sqlExecutor, primaryName, variantName, creatorID string, steps []RecipeStepV1) error {
	for _, step := range steps { //TODO: More database stuff.
		_, err := InsertIntoInstructionTableWithTx(tx, step, primaryName, variantName, creatorID)

		if err != nil {
			return fmt.Errorf("failed to insert steps: %w", err)
		}

		for _, si := range step.StepIngredients {
			_, err := InsertIntoStepIngredientsTableWithTx(tx, si, primaryName, variantName, creatorID)

			if err != nil {
				return fmt.Errorf("failed to insert step ingredients: %w", err)
			}
		}
	}

	return nil
}

func (s *RecipeServiceV1) InsertVersionIngredients(tx sqlExecutor, primaryName, variantName, creatorID string, ingredients []IngredientV1) error {

	for _, ing := range ingredients {
		_, err := InsertIntoIngredientsTableWithTx(tx, ing, primaryName, variantName, creatorID)

		if err != nil {
			return fmt.Errorf("failed to insert ingredient: %w", err)
		}
	}

	return nil
}

func (s *RecipeServiceV1) UpdateRecipe(userID, primaryName, variantName, creatorID string, data RecipeUpdateV1) error {
	return withTx(s.DB, func(tx sqlExecutor) error {

		var exists int

		//TODO: More database stuff.
		err := GetUserForUpdateRecipe(tx, primaryName, variantName, creatorID, userID).Scan(&exists)

		if errors.Is(err, sql.ErrNoRows) {
			return ErrRecipeNotFound
		}

		if err != nil {
			return fmt.Errorf("failed to verify recipe ownership: %w", err)
		}

		// currentVersionID, err := s.GetLatestVersionID(
		// 	tx, primaryName, variantName, creatorID,
		// )
		// if err != nil {
		// 	return err
		// }

		// TODO: Silvia, can you translate the new DB structure into the recipe management system?

		currentIngredients, err := s.GetIngredients(tx, primaryName, variantName, creatorID)
		if err != nil {
			return err
		}

		currentSteps, err := s.GetSteps(tx, primaryName, variantName, creatorID)
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

func (s *RecipeServiceV1) GetCookBookRecipes(userID string) ([]RecipeV1, error) {
	rows, err := GetCookBookRecipesFromCookBookTable(s, userID)

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
