package main

import (
	"database/sql"
	"fmt"

	_ "github.com/lib/pq"
)

type Storage interface {
	CreateAccount(*Account) error
	DeleteAccount(int) error
	UpdateAccount(*Account) error
	GetAccounts() ([]*Account, error)
	GetAccountByID(int) (*Account, error)
}

type PostgresStore struct {
	db *sql.DB
}

func NewPostgresStore() (*PostgresStore, error) {
	connStr := "user=postgres dbname=postgres password=gobank sslmode=disable"
	db, err := sql.Open("postgres", connStr)
	if err != nil {
		return nil, err
	}

	if err := db.Ping(); err != nil {
		return nil, err
	}

	return &PostgresStore{
		db: db,
	}, nil
}

func (s *PostgresStore) Init() error {
	return s.createAccountTable()
}

func (s *PostgresStore) createAccountTable() error {
	query := `CREATE TABLE IF NOT EXISTS account (
		id serial primary key,
		first_name varchar(50),
		last_name varchar(50),
		number serial, 
		balance integer,
		created_at timestamp
	)`
	_, err := s.db.Exec(query)

	return err
}

func (s *PostgresStore) CreateAccount(acc *Account) error {
	query := `INSERT INTO account (first_name, last_name, number, balance, created_at)
	VALUES ($1, $2, $3, $4, $5)`
	res, err := s.db.Query(
		query,
		acc.FirstName,
		acc.LastName,
		acc.Number,
		acc.Balance,
		acc.CreatedAt,
	)

	if err != nil {
		return err
	}

	fmt.Printf("%+v\n", res)

	return nil
}

func (s *PostgresStore) UpdateAccount(*Account) error {

	return nil
}

func (s *PostgresStore) DeleteAccount(id int) error {
	query := `DELETE FROM account WHERE id = $1`
	_, err := s.db.Exec(query, id)

	if err != nil {
		return err
	}

	return nil
}

func (s *PostgresStore) GetAccountByID(id int) (*Account, error) {
	query := `SELECT * FROM account WHERE id = $1`
	rows, err := s.db.Query(query, id)
	if err != nil {
		return nil, err
	}

	for rows.Next() {
		return scanIntoAccounts(rows)
	}

	return nil, fmt.Errorf("account %d not found", id)
}

func (s *PostgresStore) GetAccounts() ([]*Account, error) {
	query := `SELECT * FROM account`
	rows, err := s.db.Query(query)

	if err != nil {
		return nil, err
	}

	accounts := []*Account{}
	for rows.Next() {
		account, err := scanIntoAccounts(rows)
		if err != nil {
			return nil, err
		}

		accounts = append(accounts, account)
	}

	return accounts, nil
}

func scanIntoAccounts(rows *sql.Rows) (*Account, error) {
	account := new(Account)
	err := rows.Scan(
		&account.ID,
		&account.FirstName,
		&account.LastName,
		&account.Number,
		&account.Balance,
		&account.CreatedAt,
	)

	if err != nil {
		return nil, err
	}

	return account, nil
}
