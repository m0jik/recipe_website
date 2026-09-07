package services

import "github.com/jmoiron/sqlx"

type ShoppingListService struct {
	DB *sqlx.DB
}
