package services

import (
	"log"

	"github.com/jmoiron/sqlx"
)

type cookBook struct {
	ID       int    `db:"id"`
	UserID   string `db:"user_id"`
	RecipeID int    `db:"recipe_id"`
}

type CookBookService struct {
	db *sqlx.DB
}

func NewCookBookService(db *sqlx.DB) *CookBookService {
	return &CookBookService{db: db}
}

func (s *CookBookService) GetCookBookByUserID(userID string) ([]cookBook, error) {
	rows, err := GetCookBookFromCookBookTable(s, userID)

	if err != nil {
		return nil, err
	}

	defer func() {
		if err := rows.Close(); err != nil {
			log.Println("Error closing rows:", err)
		}
	}()

	var recipes []cookBook
	for rows.Next() {
		var c cookBook
		if err := rows.Scan(&c.ID, &c.UserID, &c.RecipeID); err != nil {
			return nil, err
		}
		recipes = append(recipes, c)
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}

	return recipes, nil
}

func (s *CookBookService) AddRecipeToCookBook(userID, primaryName, variantName, creatorID string) error {
	_, err := InsertIntoCookBookTable(s, userID, primaryName, variantName, creatorID)

	return err
}

func (s *CookBookService) RemoveRecipeFromCookBook(userID, primaryName, variantName, creatorID string) error {
	_, err := DeleteFromCookBookTable(s, userID, primaryName, variantName, creatorID)

	return err
}

func (s *CookBookService) HasRecipe(userID, primaryName, variantName, creatorID string) (bool, error) {
	var count int
	err := GetCountFromCookBookTable(s, count, userID, primaryName, variantName, creatorID)
	if err != nil {
		return false, err
	}

	return count > 0, nil
}
