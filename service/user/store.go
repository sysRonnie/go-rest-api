package user

import (
	"database/sql"
	"fmt"
	"go-rest-api/types"
)

type Store struct {
	db *sql.DB
}

func NewStore(db *sql.DB) *Store {
	return &Store{db: db}
}

func (s *Store) GetUserByEmail(email string) (*types.User, error) {
	rows, err := s.db.Query("SELECT * FROM users where email = ?", email)
	if err != nil {
		return nil, err
	}

	u := new(types.User)

	for rows.Next() {
		u, err = scanRowIntoUser(rows)
		if err != nil {
			return nil, err
		}
	}

	if u.ID == 0 {
		return nil, fmt.Errorf("user not found")
	}

	return u, nil
}

func scanRowIntoUser(rows *sql.Rows) (*types.User, error) {
	// Setting an instance of the User type and assinging it to user
	user := new(types.User)

	err := rows.Scan(
		&user.ID,
		&user.FirstName,
		&user.LastName,
		&user.Email,
		&user.Password,
		&user.CreatedAt,
	)

	if err != nil {
		return nil, err
	}

	return user, nil
}

func (s *Store) GetUserByID(id int) (*types.User, error) {
	rows, err := s.db.Query("SELECT * FROM users where id = ?", id)
	if err != nil {
		return nil, err
	}

	u := new(types.User)

	for rows.Next() {
		u, err = scanRowIntoUser(rows)
		if err != nil {
			return nil, err
		}
	}

	if u.ID == 0 {
		return nil, fmt.Errorf("user not found")
	}

	return u, nil
}

func (s *Store) CreateUser(user types.User) error {
	_, err := s.db.Exec("INSERT into users (firstName, lastName, email, password) VALUES (?, ?, ?, ?)", user.FirstName, user.LastName, user.Email, user.Password)
	if err != nil {
		return err
	}

	return nil
}
