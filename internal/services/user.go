package services

import (
	"errors"
	"strings"

	"github.com/jmoiron/sqlx"
)

var (
	ErrUserExists = errors.New("user already exists")
)

type UserService struct {
	DB *sqlx.DB
}

func NewUserService(db *sqlx.DB) *UserService {
	return &UserService{DB: db}
}

func (s *UserService) CreateUser(username, email, passwordHash string) (int, error) {
	// _, err := s.DB.Exec(
	// 	"INSERT INTO usersV1(username, email, password_hash) VALUES (?, ?, ?)",
	// 	username,
	// 	email,
	// 	passwordHash,
	// )
	// return err
	result, err := s.DB.Exec(
		"INSERT INTO usersV1(username, email, password_hash) VALUES (?, ?, ?)",
		username,
		email,
		passwordHash,
	)
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE constraint failed") {
			return 0, ErrUserExists
		}
		return 0, err
	}

	id, err := result.LastInsertId()
	if err != nil {
		return 0, err
	}

	return int(id), nil
}

func (s *UserService) GetUserCredentials(email string) (int, string, error) {
	var (
		id   int
		hash string
	)

	row := s.DB.QueryRow(
		"SELECT id, password_hash FROM usersV1 WHERE email = ?",
		email,
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

func (s *UserService) GetUserIDByEmail(email string) (int, error) {
	var id int

	row := s.DB.QueryRow(
		"SELECT id FROM usersV1 WHERE email = ?",
		email,
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

func (s *UserService) GetEmailByUsername(username string) (string, error) {
	var email string

	row := s.DB.QueryRow(
		"SELECT email FROM usersV1 WHERE username = ?",
		username,
	)

	if err := row.Scan(&email); err != nil {
		return "", err
	}

	return email, nil
}

func (s *UserService) CreateEmailVerification(userID int, token, expires string) error {
	_, err := s.DB.Exec(
		"INSERT INTO emailVerifyV1(user_id, token, expires_at) VALUES (?, ?, ?)",
		userID,
		token,
		expires,
	)

	return err
}

func (s *UserService) GetEmailVerification(token string) (int, string, error) {
	var (
		userID  int
		expires string
	)

	row := s.DB.QueryRow(
		"SELECT user_id, expires_at FROM emailVerifyV1 WHERE token = ?",
		token,
	)

	if err := row.Scan(&userID, &expires); err != nil {
		return -1, "", err
	}

	return userID, expires, nil
}

func (s *UserService) DeleteEmailVerification(token string) error {
	_, err := s.DB.Exec(
		"DELETE FROM emailVerifyV1 WHERE token = ?",
		token,
	)

	return err
}

func (s *UserService) MarkEmailVerified(userID int) error {
	_, err := s.DB.Exec(
		"UPDATE usersV1 SET is_verified = TRUE WHERE id = ?",
		userID,
	)

	return err
}

func (s *UserService) IsUserVerified(userID int) (bool, error) {
	var isVerified bool

	row := s.DB.QueryRow(
		"SELECT is_verified FROM usersV1 WHERE id = ?",
		userID,
	)

	if err := row.Scan(&isVerified); err != nil {
		return false, err
	}

	return isVerified, nil
}

func (s *UserService) VerifyEmail(token string) error {
	userID, _, err := s.GetEmailVerification(token)
	if err != nil {
		return err
	}
	if err := s.MarkEmailVerified(userID); err != nil {
		return err
	}
	return s.DeleteEmailVerification(token)
}

func (s *UserService) ValidPassword(p string) bool {
	if len(p) < 8 {
		return false
	}
	if !strings.ContainsAny(p, "0123456789") {
		return false
	}
	if !strings.ContainsAny(p, "ABCDEFGHIJKLMNOPQRSTUVWXYZ") {
		return false
	}
	if !strings.ContainsAny(p, "abcdefghijklmnopqrstuvwxyz") {
		return false
	}
	return true
}
