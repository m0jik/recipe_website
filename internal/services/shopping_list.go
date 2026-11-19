package services

import (
	"database/sql"
	"fmt"
	"log"
	"strings"

	"github.com/jmoiron/sqlx"
)

type ShoppingListSourceV1 struct {
	RecipeID    int64
	RecipeTitle string
	ImageURL    string
	Quantity    string
}

type ShoppingListItemV1 struct {
	Name       string
	Unit       string
	Need       string
	InPantry   string
	ToBuy      string
	Bought     string
	BoughtUnit string
	Checked    bool
	Sources    []ShoppingListSourceV1
}

type RecipeKeyV1 struct {
	PrimaryName string
	VariantName string
	CreatorID   string
}

func (i ShoppingListItemV1) NeedsBuying() bool {
	if i.Checked {
		return false
	}
	q, err := ParseQuantity(i.ToBuy)
	if err != nil {
		return true
	}
	return q > 0
}

// ShoppingListRecipe is a recipe the user picked
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

func (s *ShoppingListService) GetItems(userID string) ([]ShoppingListItemV1, error) {
	return s.getItems(s.DB, userID)
}

func (s *ShoppingListService) getItems(q sqlExecutor, userID string) ([]ShoppingListItemV1, error) {
	rows, err := GetItemsFromShoppingListTable(q, userID)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err := rows.Close(); err != nil {
			log.Println("Error closing rows:", err)
		}
	}()

	var items []ShoppingListItemV1
	for rows.Next() {
		var name, unit string
		var src ShoppingListSourceV1
		if err := rows.Scan(&name, &unit, &src.Quantity, &src.RecipeID, &src.RecipeTitle, &src.ImageURL); err != nil {
			return nil, err
		}

		if last := len(items) - 1; last >= 0 && items[last].Name == name && items[last].Unit == unit {
			items[last].Sources = append(items[last].Sources, src)
			continue
		}
		items = append(items, ShoppingListItemV1{
			Name:    name,
			Unit:    unit,
			Sources: []ShoppingListSourceV1{src},
		})
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	pantry, err := s.pantryAmounts(q, userID)
	if err != nil {
		return nil, err
	}
	state, err := s.itemState(q, userID)
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
			items[i].Bought = st.bought
			items[i].BoughtUnit = st.boughtUnit
		}
	}
	return items, nil
}

type lineState struct {
	checked    bool
	bought     string
	boughtUnit string
}

// itemKey matches shopping list lines to pantry and state rows. Ingredient names are typed by hand on both sides, so they are compared loosely.
func itemKey(name, unit string) [2]string {
	return [2]string{
		strings.ToLower(strings.TrimSpace(name)),
		strings.ToLower(strings.TrimSpace(unit)),
	}
}

func (s *ShoppingListService) pantryAmounts(q sqlExecutor, userID string) (map[[2]string]string, error) {
	rows, err := GetPantryAmountsFromUserPantryTable(q, userID)
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

		key := itemKey(name, unit)
		if already, ok := amounts[key]; ok {
			combined, _, ok := CombineQuantities(already, unit, quantity, unit)
			if !ok {
				continue
			}
			quantity = combined
		}
		amounts[key] = quantity
	}
	return amounts, rows.Err()
}

func (s *ShoppingListService) itemState(q sqlExecutor, userID string) (map[[2]string]lineState, error) {
	rows, err := GetItemShoppingStateFromUserShoppingStateTable(q, userID)
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
		if err := rows.Scan(&name, &unit, &st.checked, &st.bought, &st.boughtUnit); err != nil {
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
func (s *ShoppingListService) SetChecked(userID, name, unit string, checked bool) error {
	_, err := InsertIntoUserShoppingStateTable(s, userID, name, unit, checked)
	return err
}

// SetAllChecked ticks off every line currently on the list, or clears them all, for the select all box in the table header.
func (s *ShoppingListService) SetAllChecked(userID string, checked bool) error {
	if !checked {
		_, err := UpdateUserShoppingStateTable(s, userID)
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

func (s *ShoppingListService) SetBought(userID string, name, unit, qty, qtyUnit string) error {
	qty = strings.TrimSpace(qty)
	if _, err := ParseQuantity(qty); err != nil {
		return fmt.Errorf("%w: %q", ErrInvalidQuantity, qty)
	}
	_, err := InsertIntoUserShoppingStateTableForBought(s, userID, name, unit, qty, qtyUnit)
	return err
}

func (s *ShoppingListService) AddCheckedToPantry(userID string, pantry *PantryService) (int, error) {
	var moved int
	err := withTx(s.DB, func(tx sqlExecutor) error {
		items, err := s.getItems(tx, userID)
		if err != nil {
			return err
		}

		for _, item := range items {
			if !item.Checked {
				continue
			}

			qty, unit := item.ToBuy, item.Unit
			if item.Bought != "" {
				qty = item.Bought
				if item.BoughtUnit != "" {
					unit = item.BoughtUnit
				}
			}

			if quantity, err := ParseQuantity(qty); err == nil && quantity > 0 {
				if err := pantry.addPantryItem(tx, userID, item.Name, FormatQuantity(quantity), unit); err != nil {
					return err
				}
				moved++
			}

			if err := s.removeItem(tx, userID, item.Name, item.Unit); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		// transaction rolled back
		return 0, err
	}
	return moved, nil
}

// GetRecipes returns the recipes feeding the list, one row per recipe even when ingredients from more than one of its versions are on there.
func (s *ShoppingListService) GetRecipes(userID string) ([]ShoppingListRecipe, error) {
	rows, err := GetRecipesFromShoppingListTable(s, userID)
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

func (s *ShoppingListService) OutdatedRecipes(userID string, recipeService *RecipeServiceV1) (map[RecipeKeyV1]bool, error) {
	rows, err := GetOutdatedRecipes(s, userID)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err := rows.Close(); err != nil {
			log.Println("Error closing rows:", err)
		}
	}()

	savedVersions := make(map[RecipeKeyV1]int64)
	for rows.Next() {
		var versionID int64
		var recipeKey RecipeKeyV1
		if err := rows.Scan(&recipeKey.PrimaryName, &recipeKey.VariantName, &recipeKey.CreatorID, &versionID); err != nil {
			return nil, err
		}
		savedVersions[recipeKey] = versionID
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	outdated := make(map[RecipeKeyV1]bool)
	for recipeKey, savedID := range savedVersions {
		latestID, err := recipeService.GetLatestVersionID(s.DB, recipeKey.PrimaryName, recipeKey.VariantName, recipeKey.CreatorID)
		if err != nil {
			return nil, err
		}
		if latestID == savedID {
			continue
		}

		saved, err := recipeService.GetIngredients(s.DB, recipeKey.PrimaryName, recipeKey.VariantName, recipeKey.CreatorID)
		if err != nil {
			return nil, err
		}
		latest, err := recipeService.GetIngredients(s.DB, recipeKey.PrimaryName, recipeKey.VariantName, recipeKey.CreatorID)
		if err != nil {
			return nil, err
		}
		if !ingredientsEqual(saved, latest) {
			outdated[recipeKey] = true
		}
	}
	return outdated, nil
}

func (s *ShoppingListService) HasRecipe(userID, primaryName, variantName, creatorID string) (bool, error) {
	var exists bool
	err := SelectExistsFromShoppingListTable(s, userID, primaryName, variantName, creatorID).Scan(&exists)
	return exists, err
}

func (s *ShoppingListService) AddRecipeIngredients(userID string, versionID int64, ingredients []IngredientV1) error {
	tx, err := s.DB.Begin()
	if err != nil {
		return err
	}
	defer func() {
		if err := tx.Rollback(); err != nil && err != sql.ErrTxDone {
			log.Println("Error rolling back shopping list add:", err)
		}
	}()

	_, err = DeleteFromUserShoppingListWhenAddingIngredient(tx, userID, versionID)
	if err != nil {
		return err
	}

	for _, ing := range mergeIngredients(ingredients) {
		_, err := InsertIntoUserShoppingListTable(tx, ing, userID, versionID)
		if err != nil {
			return err
		}
	}
	if err := s.removeUnusedState(tx, userID); err != nil {
		return err
	}
	return tx.Commit()
}

func mergeIngredients(ingredients []IngredientV1) []IngredientV1 {
	var merged []IngredientV1
	seen := make(map[[2]string]int, len(ingredients))

	for _, ing := range ingredients {
		if ing.Name == "" {
			continue
		}
		key := itemKey(ing.Name, ing.Unit)
		i, ok := seen[key]
		if !ok {
			seen[key] = len(merged)
			merged = append(merged, ing)
			continue
		}
		if amnt, _, ok := CombineQuantities(merged[i].Amount, merged[i].Unit, ing.Amount, ing.Unit); ok {
			merged[i].Amount = amnt
		} else {
			merged[i].Amount = merged[i].Amount + " + " + ing.Amount
		}
	}
	return merged
}

func (s *ShoppingListService) removeItem(q sqlExecutor, userID, name, unit string) error {
	_, err := DeleteFromShoppingListWhenRemovingItem(q, userID, name, unit)
	if err != nil {
		return err
	}
	_, err = DeleteFromShoppingStateWhenRemovingItem(q, userID, name, unit)
	return err
}

func (s *ShoppingListService) removeUnusedState(q sqlExecutor, userID string) error {
	_, err := DeleteFromShoppingStateWhenRemovingUnusedState(q, userID)
	return err
}

// RemoveRecipe drops every ingredient that came from any version of a recipe.
func (s *ShoppingListService) RemoveRecipe(userID string, recipeID int64) error {
	return withTx(s.DB, func(tx sqlExecutor) error {
		_, err := DeleteFromShoppingListWhenRemovingRecipe(tx, userID, recipeID)
		if err != nil {
			return err
		}
		return s.removeUnusedState(tx, userID)
	})
}

func totalQuantity(sources []ShoppingListSourceV1) string {
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
