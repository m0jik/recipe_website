package services

import (
	"errors"
	"fmt"
	"log"

	"github.com/jmoiron/sqlx"
)

var ErrInvalidQuantity = errors.New("invalid quantity")

type PantryIngredient struct {
	ID       int64
	Name     string
	Quantity string
	Unit     string
}

type PantryService struct {
	DB *sqlx.DB
}

func NewPantryService(db *sqlx.DB) *PantryService {
	return &PantryService{DB: db}
}

func (s *PantryService) GetPantryItems(userID int) ([]PantryIngredient, error) {
	rows, err := s.DB.Query(
		"SELECT rowid, name, quantity, unit FROM userPantryV1 WHERE user_id = ? ORDER BY name, unit",
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

	var items []PantryIngredient
	for rows.Next() {
		var p PantryIngredient
		if err := rows.Scan(&p.ID, &p.Name, &p.Quantity, &p.Unit); err != nil {
			return nil, err
		}
		items = append(items, p)
	}
	return items, nil
}

func (s *PantryService) AddPantryItem(userID int, name, quantity, unit string) error {
	if _, err := ParseQuantity(quantity); err != nil {
		return fmt.Errorf("%w: %q", ErrInvalidQuantity, quantity)
	}

	rows, err := s.DB.Query(
		"SELECT quantity, unit FROM userPantryV1 WHERE user_id = ? AND name = ?",
		userID, name,
	)
	if err != nil {
		return err
	}

	type existingRow struct{ qty, unit string }
	var existing []existingRow
	for rows.Next() {
		var e existingRow
		if err := rows.Scan(&e.qty, &e.unit); err != nil {
			rows.Close()
			return err
		}
		existing = append(existing, e)
	}
	if err := rows.Close(); err != nil {
		return err
	}

	for _, e := range existing {
		combinedQty, combinedUnit, ok := CombineQuantities(e.qty, e.unit, quantity, unit)
		if !ok {
			continue
		}
		_, err = s.DB.Exec(
			"UPDATE userPantryV1 SET quantity = ?, unit = ? WHERE user_id = ? AND name = ? AND unit = ?",
			combinedQty, combinedUnit, userID, name, e.unit,
		)
		return err
	}

	_, err = s.DB.Exec(
		`INSERT INTO userPantryV1 (user_id, name, quantity, unit) VALUES (?, ?, ?, ?)
		 ON CONFLICT(user_id, name, unit) DO UPDATE SET quantity = excluded.quantity`,
		userID, name, quantity, unit,
	)
	return err
}

func (s *PantryService) RemovePantryItem(userID int, name, unit string) error {
	_, err := s.DB.Exec("DELETE FROM userPantryV1 WHERE user_id = ? AND name = ? AND unit = ?", userID, name, unit)
	return err
}
