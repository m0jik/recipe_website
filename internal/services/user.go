package services

import "github.com/jmoiron/sqlx"

type UserService struct {
	DB *sqlx.DB
}

func NewUserService(db *sqlx.DB) *UserService {
	return &UserService{DB: db}
}

func (s *UserService) CreateUser(username, passwordHash string) error {
	_, err := s.DB.Exec(
		"INSERT INTO usersV1(username, password_hash) VALUES (?, ?)",
		username, passwordHash,
	)
	return err
}

func (s *UserService) GetUserCredentials(username string) (int, string, error) {
	var (
		id   int
		hash string
	)

	row := s.DB.QueryRow(
		"SELECT id, password_hash FROM usersV1 WHERE username = ?",
		username,
	)

	if err := row.Scan(&id, &hash); err != nil {
		return 0, "", err
	}

	return id, hash, nil
}
