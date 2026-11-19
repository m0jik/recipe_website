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

func (s *PantryService) GetPantryItems(userID string) ([]PantryIngredient, error) {
	rows, err := GetItemsFromUserPantryTable(s, userID)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err := rows.Close(); err != nil {
			log.Println("Error closing rows:", err)
		}
	}()

	if err := rows.Err(); err != nil {
		log.Println("Error iterating over rows:", err)
	}

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

func (s *PantryService) AddPantryItem(userID string, name, quantity, unit string) error {
	return s.addPantryItem(s.DB, userID, name, quantity, unit)
}

func (s *PantryService) addPantryItem(q sqlExecutor, userID string, name, quantity, unit string) error {
	if _, err := ParseQuantity(quantity); err != nil {
		return fmt.Errorf("%w: %q", ErrInvalidQuantity, quantity)
	}
	rows, err := GetPantryItemsWhenAddingItem(q, userID, name)
	if err != nil {
		return err
	}

	type existingRow struct{ name, qty, unit string }
	var existing []existingRow
	for rows.Next() {
		var e existingRow
		if err := rows.Scan(&e.name, &e.qty, &e.unit); err != nil {
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
		_, err = UpdateUserPantryTable(q, e.name, e.unit, combinedQty, combinedUnit, userID)
		return err
	}

	_, err = InsertIntoUserPantryTable(q, userID, name, quantity, unit)
	return err
}

func (s *PantryService) RemovePantryItem(userID string, name, unit string) error {
	_, err := DeleteFromUserPantryTable(s, userID, name, unit)
	return err
}
