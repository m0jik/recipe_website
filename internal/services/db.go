package services

import (
	"database/sql"
	"log"

	"github.com/jmoiron/sqlx"
)

type sqlExecutor interface {
	Query(query string, args ...any) (*sql.Rows, error)
	Exec(query string, args ...any) (sql.Result, error)
}

func withTx(db *sqlx.DB, fn func(tx sqlExecutor) error) error {
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer func() {
		if err := tx.Rollback(); err != nil && err != sql.ErrTxDone {
			log.Println("Error rolling back transaction:", err)
		}
	}()

	if err := fn(tx); err != nil {
		return err
	}
	return tx.Commit()
}
