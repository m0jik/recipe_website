// Package services provides the UserService struct and its methods for managing user accounts, sessions, password resets, and email verification.
package services

import (
	"errors"
	"strings"

	"github.com/jmoiron/sqlx"
)

var ErrUserExists = errors.New("user already exists")

type UserServiceV1 struct {
	DB *sqlx.DB
}

func NewUserService(db *sqlx.DB) *UserServiceV1 {
	return &UserServiceV1{DB: db}
}

func (s *UserServiceV1) CreateUser(username, email, passwordHash string) (string, error) {
	// _, err := s.DB.Exec(
	// 	"INSERT INTO usersV1(username, email, password_hash) VALUES (?, ?, ?)",
	// 	username,
	// 	email,
	// 	passwordHash,
	// )
	// return err
	_, err := InsertIntoUsersTable(s, username, email, passwordHash)
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE constraint failed") {
			return "", ErrUserExists
		}
		return "", err
	}

	return string(username), nil
}

func (s *UserServiceV1) GetUserCredentials(email string) (string, string, error) {
	var (
		id   string
		hash string
	)

	row := GetPasswordHash(s, email)

	if err := row.Scan(&id, &hash); err != nil {
		return "", "", err
	}

	return id, hash, nil
}

func (s *UserServiceV1) GetUsernameByID(id string) (string, error) {
	var username string

	row := GetUsername(s, id)

	if err := row.Scan(&username); err != nil {
		return "", err
	}

	return username, nil
}

func (s *UserServiceV1) CreateSession(sessionID, id, expires string) error {
	_, err := InsertIntoSessionsTable(s, sessionID, expires, id)
	return err
}

func (s *UserServiceV1) DeleteSession(val string) error {
	_, err := DeleteFromSessionsTable(s, val)
	return err
}

func (s *UserServiceV1) GetUserID(val string) (string, string, error) {
	var (
		id      string
		expires string
	)

	row := GetUserIDFromSessionsTable(s, val)

	if err := row.Scan(&id, &expires); err != nil {
		return "", "", err
	}

	return id, expires, nil
}

func (s *UserServiceV1) GetUserIDByEmail(email string) (string, error) {
	var id string

	row := GetUserIDFromUsersTableByEmail(s, email)

	if err := row.Scan(&id); err != nil {
		return "", err
	}

	return id, nil
}

func (s *UserServiceV1) CreatePasswordReset(userID string, token, expires string) error {
	_, err := InsertIntoPassResetTable(s, userID, token, expires)
	return err
}

func (s *UserServiceV1) GetPasswordReset(token string) (string, string, error) {
	var (
		userID  string
		expires string
	)

	row := GetUserIDFromPassResetTable(s, token)

	if err := row.Scan(&userID, &expires); err != nil {
		return "", "", err
	}

	return userID, expires, nil
}

func (s *UserServiceV1) UpdatePassword(userID, hash string) error {
	_, err := UpdateUsersTable(s, userID, hash)
	return err
}

func (s *UserServiceV1) DeletePasswordReset(token string) error {
	_, err := DeleteFromPassResetTable(s, token)
	return err
}

func (s *UserServiceV1) GetEmailByUsername(username string) (string, error) {
	var email string

	row := GetEmailFromUsersTable(s, username)

	if err := row.Scan(&email); err != nil {
		return "", err
	}

	return email, nil
}

func (s *UserServiceV1) CreateEmailVerification(userID, token, expires string) error {
	_, err := InsertIntoEmailVerifyTable(s, userID, token, expires)

	return err
}

func (s *UserServiceV1) GetEmailVerification(token string) (string, string, error) {
	var (
		userID  string
		expires string
	)

	row := GetUserIDFromEmailVerifyTable(s, token)

	if err := row.Scan(&userID, &expires); err != nil {
		return "", "", err
	}

	return userID, expires, nil
}

func (s *UserServiceV1) DeleteEmailVerification(token string) error {
	_, err := DeleteFromEmailVerifyTable(s, token)

	return err
}

func (s *UserServiceV1) MarkEmailVerified(userID string) error {
	_, err := UpdateUsersTableWithVerification(s, userID)

	return err
}

func (s *UserServiceV1) IsUserVerified(userID string) (bool, error) {
	var isVerified bool

	row := GetIsUserVerified(s, userID)

	if err := row.Scan(&isVerified); err != nil {
		return false, err
	}

	return isVerified, nil
}

func (s *UserServiceV1) VerifyEmail(token string) error {
	userID, _, err := s.GetEmailVerification(token)
	if err != nil {
		return err
	}
	if err := s.MarkEmailVerified(userID); err != nil {
		return err
	}
	return s.DeleteEmailVerification(token)
}

func (s *UserServiceV1) ValidPassword(p string) bool {
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
