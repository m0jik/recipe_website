package services

import "github.com/jmoiron/sqlx"

type PantryService struct {
	DB *sqlx.DB
}

func NewPantryService(db *sqlx.DB) *PantryService {
	return &PantryService{DB: db}
}
