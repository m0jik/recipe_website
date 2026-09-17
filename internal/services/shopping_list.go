package services

import (
	"database/sql"
	"log"
	"strings"

	"github.com/jmoiron/sqlx"
)

type ShoppingListSource struct {
	RecipeID    int64
	RecipeTitle string
	ImageURL    string
	Quantity    string
}

type ShoppingListItem struct {
	Name string
	Unit string
	// Need is what the recipes add up to, InPantry what the user already has,
	// and ToBuy the difference the shopper actually takes to the shop. ToBuy is
	// overridden outright once the user nudges it with the quantity stepper.
	Need       string
	InPantry   string
	ToBuy      string
	Checked    bool
	Overridden bool
	Sources    []ShoppingListSource
}

// NeedsBuying reports whether a line still has to be bought, which is what the
// "show only what I need to buy" filter keeps. Quantities that would not parse
// are kept rather than hidden, since we cannot prove they are covered.
func (i ShoppingListItem) NeedsBuying() bool {
	if i.Checked {
		return false
	}
	q, err := ParseQuantity(i.ToBuy)
	if err != nil {
		return true
	}
	return q > 0
}

// ShoppingListRecipe is a recipe the user picked, shown above the list itself.
type ShoppingListRecipe struct {
	ID       int64
	Title    string
	ImageURL string
	Servings int
}

type ShoppingListService struct {
	DB *sqlx.DB
}

func NewShoppingListService(db *sqlx.DB) *ShoppingListService {
	return &ShoppingListService{DB: db}
}

// GetItems returns the list grouped by ingredient. Rows are stored one per
// recipe, so the grouping and the adding up both happen here, along with
// subtracting whatever the user's pantry already covers.
func (s *ShoppingListService) GetItems(userID int) ([]ShoppingListItem, error) {
	rows, err := s.DB.Query(
		`SELECT sl.name, sl.unit, sl.quantity,
		        COALESCE(r.id, 0), COALESCE(r.title, ''), COALESCE(r.image_url, '')
		 FROM userShoppingListV2 sl
		 LEFT JOIN recipe_versionsV1 rv ON rv.id = sl.source_recipe_version_id
		 LEFT JOIN recipesV1 r ON r.id = rv.recipe_id
		 WHERE sl.user_id = ?
		 ORDER BY sl.name, sl.unit, r.title`,
		userID,
	)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err := rows.Close(); err != nil {
			log.Println("Error closing rows:", err)
		}
	}()

	var items []ShoppingListItem
	for rows.Next() {
		var name, unit string
		var src ShoppingListSource
		if err := rows.Scan(&name, &unit, &src.Quantity, &src.RecipeID, &src.RecipeTitle, &src.ImageURL); err != nil {
			return nil, err
		}

		if last := len(items) - 1; last >= 0 && items[last].Name == name && items[last].Unit == unit {
			items[last].Sources = append(items[last].Sources, src)
			continue
		}
		items = append(items, ShoppingListItem{
			Name:    name,
			Unit:    unit,
			Sources: []ShoppingListSource{src},
		})
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	pantry, err := s.pantryAmounts(userID)
	if err != nil {
		return nil, err
	}
	state, err := s.itemState(userID)
	if err != nil {
		return nil, err
	}

	for i := range items {
		key := itemKey(items[i].Name, items[i].Unit)

		items[i].Need = totalQuantity(items[i].Sources)
		items[i].InPantry = pantry[key]
		if items[i].InPantry == "" {
			items[i].InPantry = "0"
		}
		items[i].ToBuy = remainingToBuy(items[i].Need, items[i].InPantry)

		if st, ok := state[key]; ok {
			items[i].Checked = st.checked
			if st.override != "" {
				items[i].ToBuy = st.override
				items[i].Overridden = true
			}
		}
	}
	return items, nil
}

type lineState struct {
	checked  bool
	override string
}

// itemKey matches shopping list lines to pantry and state rows. Ingredient names are typed by hand on both sides, so they are compared loosely.
func itemKey(name, unit string) [2]string {
	return [2]string{
		strings.ToLower(strings.TrimSpace(name)),
		strings.ToLower(strings.TrimSpace(unit)),
	}
}

func (s *ShoppingListService) pantryAmounts(userID int) (map[[2]string]string, error) {
	rows, err := s.DB.Query(
		"SELECT name, unit, quantity FROM userPantryV1 WHERE user_id = ?", userID,
	)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err := rows.Close(); err != nil {
			log.Println("Error closing rows:", err)
		}
	}()

	amounts := make(map[[2]string]string)
	for rows.Next() {
		var name, unit, quantity string
		if err := rows.Scan(&name, &unit, &quantity); err != nil {
			return nil, err
		}
		amounts[itemKey(name, unit)] = quantity
	}
	return amounts, rows.Err()
}

func (s *ShoppingListService) itemState(userID int) (map[[2]string]lineState, error) {
	rows, err := s.DB.Query(
		"SELECT name, unit, checked, qty_override FROM userShoppingStateV1 WHERE user_id = ?", userID,
	)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err := rows.Close(); err != nil {
			log.Println("Error closing rows:", err)
		}
	}()

	state := make(map[[2]string]lineState)
	for rows.Next() {
		var name, unit string
		var st lineState
		if err := rows.Scan(&name, &unit, &st.checked, &st.override); err != nil {
			return nil, err
		}
		state[itemKey(name, unit)] = st
	}
	return state, rows.Err()
}

func remainingToBuy(need, inPantry string) string {
	needQty, err := ParseQuantity(need)
	if err != nil || need == "" {
		return need
	}
	pantryQty, err := ParseQuantity(inPantry)
	if err != nil {
		return need
	}
	if remaining := needQty - pantryQty; remaining > 0 {
		return FormatQuantity(remaining)
	}
	return "0"
}

// SetChecked ticks a line off in the aisle, or puts it back.
func (s *ShoppingListService) SetChecked(userID int, name, unit string, checked bool) error {
	_, err := s.DB.Exec(
		`INSERT INTO userShoppingStateV1 (user_id, name, unit, checked)
		 VALUES (?, ?, ?, ?)
		 ON CONFLICT(user_id, name, unit) DO UPDATE SET checked = excluded.checked`,
		userID, name, unit, checked,
	)
	return err
}

// SetAllChecked ticks off every line currently on the list, or clears them all, for the select all box in the table header.
func (s *ShoppingListService) SetAllChecked(userID int, checked bool) error {
	if !checked {
		_, err := s.DB.Exec("UPDATE userShoppingStateV1 SET checked = 0 WHERE user_id = ?", userID)
		return err
	}

	items, err := s.GetItems(userID)
	if err != nil {
		return err
	}
	for _, item := range items {
		if err := s.SetChecked(userID, item.Name, item.Unit, true); err != nil {
			return err
		}
	}
	return nil
}

// AdjustQuantity nudges how much of a line to actually buy by delta, starting from whatever is currently shown. It never goes below zero.
func (s *ShoppingListService) AdjustQuantity(userID int, name, unit string, delta float64) error {
	items, err := s.GetItems(userID)
	if err != nil {
		return err
	}

	key := itemKey(name, unit)
	for _, item := range items {
		if itemKey(item.Name, item.Unit) != key {
			continue
		}
		current, err := ParseQuantity(item.ToBuy)
		if err != nil {
			// Nothing numeric to step, so leave the wording alone.
			return nil
		}
		updated := current + delta
		if updated < 0 {
			updated = 0
		}
		_, err = s.DB.Exec(
			`INSERT INTO userShoppingStateV1 (user_id, name, unit, qty_override)
			 VALUES (?, ?, ?, ?)
			 ON CONFLICT(user_id, name, unit) DO UPDATE SET qty_override = excluded.qty_override`,
			userID, item.Name, item.Unit, FormatQuantity(updated),
		)
		return err
	}
	return nil
}

// clearState drops the tick and any override for a line, used when the line
// itself leaves the list so a later re-add starts clean.
func (s *ShoppingListService) clearState(userID int, name, unit string) error {
	_, err := s.DB.Exec(
		"DELETE FROM userShoppingStateV1 WHERE user_id = ? AND name = ? AND unit = ?",
		userID, name, unit,
	)
	return err
}

// GetRecipes returns the recipes feeding the list, one row per recipe even when ingredients from more than one of its versions are on there.
func (s *ShoppingListService) GetRecipes(userID int) ([]ShoppingListRecipe, error) {
	rows, err := s.DB.Query(
		`SELECT DISTINCT r.id, r.title, COALESCE(r.image_url, ''), COALESCE(r.servings, 0)
		 FROM userShoppingListV2 sl
		 JOIN recipe_versionsV1 rv ON rv.id = sl.source_recipe_version_id
		 JOIN recipesV1 r ON r.id = rv.recipe_id
		 WHERE sl.user_id = ?
		 ORDER BY r.title`,
		userID,
	)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err := rows.Close(); err != nil {
			log.Println("Error closing rows:", err)
		}
	}()

	var recipes []ShoppingListRecipe
	for rows.Next() {
		var rec ShoppingListRecipe
		if err := rows.Scan(&rec.ID, &rec.Title, &rec.ImageURL, &rec.Servings); err != nil {
			return nil, err
		}
		recipes = append(recipes, rec)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return recipes, nil
}

// HasRecipe reports whether any version of a recipe is already feeding the
// user's list, so a page can render the cart button in its "already added"
// state instead of assuming a fresh one.
func (s *ShoppingListService) HasRecipe(userID int, recipeID int64) (bool, error) {
	var exists bool
	err := s.DB.QueryRow(
		`SELECT EXISTS (
		     SELECT 1 FROM userShoppingListV2 sl
		     JOIN recipe_versionsV1 rv ON rv.id = sl.source_recipe_version_id
		     WHERE sl.user_id = ? AND rv.recipe_id = ?
		 )`,
		userID, recipeID,
	).Scan(&exists)
	return exists, err
}

// AddRecipeIngredients replaces whatever a recipe had already put on the list
// with the ingredients of the version being added. Rows are unique per
// (name, unit, version), so a recipe listing the same ingredient twice would
// otherwise overwrite itself.
func (s *ShoppingListService) AddRecipeIngredients(userID int, versionID int64, ingredients []Ingredient) error {
	tx, err := s.DB.Begin()
	if err != nil {
		return err
	}
	defer func() {
		if err := tx.Rollback(); err != nil && err != sql.ErrTxDone {
			log.Println("Error rolling back shopping list add:", err)
		}
	}()

	_, err = tx.Exec(
		`DELETE FROM userShoppingListV2
		 WHERE user_id = ?
		   AND source_recipe_version_id IN (
		       SELECT id FROM recipe_versionsV1
		       WHERE recipe_id = (SELECT recipe_id FROM recipe_versionsV1 WHERE id = ?)
		   )`,
		userID, versionID,
	)
	if err != nil {
		return err
	}

	for _, ing := range mergeIngredients(ingredients) {
		_, err := tx.Exec(
			`INSERT INTO userShoppingListV2 (user_id, name, quantity, unit, source_recipe_version_id)
			 VALUES (?, ?, ?, ?, ?)
			 ON CONFLICT(user_id, name, unit, source_recipe_version_id)
			 DO UPDATE SET quantity = excluded.quantity`,
			userID, ing.Name, ing.Quantity, ing.Unit, versionID,
		)
		if err != nil {
			return err
		}
	}
	return tx.Commit()
}

// mergeIngredients folds a recipe's repeated ingredients into one row each,
// keeping the original order. Quantities that will not parse (a "pinch") are
// kept side by side rather than dropped.
func mergeIngredients(ingredients []Ingredient) []Ingredient {
	var merged []Ingredient
	seen := make(map[[2]string]int, len(ingredients))

	for _, ing := range ingredients {
		if ing.Name == "" {
			continue
		}
		key := [2]string{strings.ToLower(ing.Name), strings.ToLower(strings.TrimSpace(ing.Unit))}
		i, ok := seen[key]
		if !ok {
			seen[key] = len(merged)
			merged = append(merged, ing)
			continue
		}
		if qty, _, ok := CombineQuantities(merged[i].Quantity, merged[i].Unit, ing.Quantity, ing.Unit); ok {
			merged[i].Quantity = qty
		} else {
			merged[i].Quantity = merged[i].Quantity + " + " + ing.Quantity
		}
	}
	return merged
}

func (s *ShoppingListService) RemoveItem(userID int, name, unit string) error {
	_, err := s.DB.Exec(
		"DELETE FROM userShoppingListV2 WHERE user_id = ? AND name = ? AND unit = ?",
		userID, name, unit,
	)
	if err != nil {
		return err
	}
	return s.clearState(userID, name, unit)
}

// RemoveRecipe drops every ingredient that came from any version of a recipe.
func (s *ShoppingListService) RemoveRecipe(userID int, recipeID int64) error {
	_, err := s.DB.Exec(
		`DELETE FROM userShoppingListV2
		 WHERE user_id = ?
		   AND source_recipe_version_id IN (
		       SELECT id FROM recipe_versionsV1 WHERE recipe_id = ?
		   )`,
		userID, recipeID,
	)
	return err
}

func totalQuantity(sources []ShoppingListSource) string {
	var total float64
	for _, src := range sources {
		q, err := ParseQuantity(src.Quantity)
		if err != nil {
			return ""
		}
		total += q
	}
	return FormatQuantity(total)
}
