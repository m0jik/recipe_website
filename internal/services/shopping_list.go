package services

import "github.com/jmoiron/sqlx"

type ShoppingListService struct {
	DB *sqlx.DB
}

func NewShoppingListService(db *sqlx.DB) *ShoppingListService {
	return &ShoppingListService{DB: db}
}
