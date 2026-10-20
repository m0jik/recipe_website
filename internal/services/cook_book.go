package services

import (
	"errors"
	"fmt"
	"log"

	"github.com/jmoiron/sqlx"
)

type cookBook struct {
	ID int `db:"id"`
	UserID int `db:"user_id"`
	RecipeID int `db:"recipe_id"`
	SourceRecipeVersionID int `db:"source_recipe_version_id"`
}

type CookBookService struct {
	db *sqlx.DB
}

func NewCookBookService(db *sqlx.DB) *CookBookService {
	return &CookBookService{db : db}
}

func (s *CookBookService) CreateCookBook(cookBook *cookBook) error {
	query := 'INSERT INTO '
}