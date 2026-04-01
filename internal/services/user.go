package services

import (
	"github.com/jmoiron/sqlx"
)

type UserService struct {
	DB *sqlx.DB
}

func NewUserService(db *sqlx.DB) *UserService {
	return &UserService{DB: db}
}

func (s *UserService) CreateUser(username, passwordHash string) error {
	_, err := s.DB.Exec(
		"INSERT INTO usersV1(username, password_hash) VALUES (?, ?)",
		username,
		passwordHash,
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

func (s *UserService) GetUsernameByID(id int) (string, error) {
	var username string

	row := s.DB.QueryRow(
		"SELECT username FROM usersV1 WHERE id = ?",
		id,
	)

	if err := row.Scan(&username); err != nil {
		return "", err
	}

	return username, nil
}

func (s *UserService) CreateSession(sessionID string, id int, expires string) error {
	_, err := s.DB.Exec(
		"INSERT INTO sessionsV1(id, user_id, expires_at) VALUES (?, ?, ?)",
		sessionID,
		id,
		expires,
	)
	return err
}

func (s *UserService) DeleteSession(val string) error {
	_, err := s.DB.Exec(
		"DELETE FROM sessionsV1 WHERE id = ?",
		val,
	)
	return err
}

func (s *UserService) GetUserID(val string) (int, string, error) {
	var (
		id      int
		expires string
	)

	row := s.DB.QueryRow(
		"SELECT user_id, expires_at FROM sessionsV1 WHERE id = ?",
		val,
	)

	if err := row.Scan(&id, &expires); err != nil {
		return -1, "", err
	}

	return id, expires, nil
}

func (s *UserService) GetUserIDByUsername(username string) (int, error) {
	var id int

	row := s.DB.QueryRow(
		"SELECT id FROM usersV1 WHERE username = ?",
		username,
	)

	if err := row.Scan(&id); err != nil {
		return -1, err
	}

	return id, nil
}

func (s *UserService) CreatePasswordReset(userID int, token, expires string) error {
	_, err := s.DB.Exec(
		"INSERT INTO passResetV1(user_id, token, expires_at) VALUES (?, ?, ?)",
		userID,
		token,
		expires,
	)
	return err
}

func (s *UserService) GetPasswordReset(token string) (int, string, error) {
	var (
		userID  int
		expires string
	)

	row := s.DB.QueryRow(
		"SELECT user_id, expires_at FROM passResetV1 WHERE token = ?",
		token,
	)

	if err := row.Scan(&userID, &expires); err != nil {
		return -1, "", err
	}

	return userID, expires, nil
}

func (s *UserService) UpdatePassword(userID int, hash string) error {
	_, err := s.DB.Exec(
		"UPDATE usersV1 SET password_hash = ? WHERE id = ?",
		hash,
		userID,
	)
	return err
}

func (s *UserService) DeletePasswordReset(token string) error {
	_, err := s.DB.Exec(
		"DELETE FROM passResetV1 WHERE token = ?",
		token,
	)
	return err
}
