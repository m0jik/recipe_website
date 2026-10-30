package services

import (
	"log"

	"github.com/jmoiron/sqlx"
)

type cookBook struct {
	ID       int `db:"id"`
	UserID   int `db:"user_id"`
	RecipeID int `db:"recipe_id"`
}

type CookBookService struct {
	db *sqlx.DB
}

func NewCookBookService(db *sqlx.DB) *CookBookService {
	return &CookBookService{db: db}
}

func (s *CookBookService) GetCookBookByUserID(userID int) ([]cookBook, error) {
	rows, err := s.db.Query(
		"SELECT id, user_id, recipe_id, source_recipe_version_id FROM cookBookV1 WHERE user_id = ?",
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
	_, err := s.db.Exec(
		"INSERT INTO cookBookV1 (user_id, recipe_id) VALUES (?, ?) ON CONFLICT(user_id, recipe_id) DO NOTHING",
		userID, primaryName, variantName, creatorID,
	)

	return err
}

func (s *CookBookService) RemoveRecipeFromCookBook(userID, primaryName, variantName, creatorID string) error {
	_, err := s.db.Exec(
		"DELETE FROM cookBookV1 where user_id = ? and recipe_id = ?",
		userID, primaryName, variantName, creatorID,
	)

	return err
}

func (s *CookBookService) HasRecipe(userID, primaryName, variantName, creatorID string) (bool, error) {
	var count int
	err := s.db.Get(&count, "SELECT COUNT(*) FROM cookBookV1 WHERE user_id = ? AND recipe_id = ?", userID, primaryName, variantName, creatorID)
	if err != nil {
		return false, err
	}

	return count > 0, nil
}
