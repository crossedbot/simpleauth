package database

import (
	"context"
	"errors"
	"fmt"
	"strings"

	cdb "github.com/crossedbot/common/golang/db"
	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/crossedbot/simpleauth/pkg/models"
)

const (
	// Database dialects
	DialectMySQL     = "mysql"
	DialectPostgres  = "prostgres"
	DialectSqlite3   = "sqlite3"
	DialectSqlServer = "sqlserver"
)

var (
	// Errors
	ErrUserExists = errors.New("The username, email or phone number already exists")
)

// Database represents an interface to the authentication database and the
// management of users.
type Database interface {
	// GetUser returns the user for the given user ID. This ID is not to be
	// confused with the records ID in the table but the generated value for the
	// user_id field.
	GetUser(id string) (models.User, error)

	// GetUserByName returns the user for the given name. This name can be
	// either the username or email address of the user as an identifier.
	GetUserByName(name string) (models.User, error)

	// SaveUser adds the given user to the database. It should fill in the
	// remaining fields like the record and user ID.
	SaveUser(user models.User) (models.User, error)

	// SetPublicKey updates the user for the given user ID and sets the user's
	// public key.
	SetPublicKey(userId, pubKey string) error

	// UpdateTotp updates the TOTP state of the user for the given user ID.
	// Either enabling TOTP and/or setting its value itself.
	UpdateTotp(enable bool, totp, userId string) error

	// UpdateTokens updates the user's access and refresh token for the given
	// user ID.
	UpdateTokens(token, refreshToken, userId string) error
}

// database represents an authentication database.
type database struct {
	Ctx     context.Context
	Dialect string
	Path    string
	Db      cdb.Database
}

// New returns a new authentication database for the context, dialect, and URI
// path to the database. For accepted dialects see the Dialect* constants, E.g.
// DialectPostgres.
func New(ctx context.Context, dialect, path string) (Database, error) {
	dialect = strings.ToLower(dialect)
	db := &database{
		Ctx:     ctx,
		Dialect: dialect,
		Path:    path,
		Db:      cdb.New(dialect),
	}
	if err := db.Db.Open(path); err != nil {
		return nil, err
	}
	return db, nil
}

func (db *database) GetUser(id string) (models.User, error) {
	var user models.User
	err := db.Db.Read(&user, "user_id = ?", id)
	if err != nil {
		return models.User{}, err
	}
	return user, nil
}

func (db *database) GetUserByName(name string) (models.User, error) {
	var user models.User
	err := db.Db.Read(&user, "username = ? OR email = ?", name, name)
	if err != nil {
		return models.User{}, err
	}
	return user, nil
}

func (db *database) SaveUser(user models.User) (models.User, error) {
	// Check if the user's username, email, or phone number already exists, if
	// they do the user is considered to exist and an error is returned.
	user.Username = strings.ToLower(user.Username)
	user.Email = strings.ToLower(user.Email)
	query := "username = ?"
	args := []interface{}{user.Username}
	if user.Email != "" {
		query = fmt.Sprintf("%s OR email = ?", query)
		args = append(args, user.Email)
	}
	if user.Phone != "" {
		query = fmt.Sprintf("%s OR phone = ?", query)
		args = append(args, user.Phone)
	}
	var foundUser models.User
	err := db.Db.Read(&foundUser, query, args...)
	if err != nil && err != gorm.ErrRecordNotFound {
		return models.User{}, err
	} else if err == gorm.ErrRecordNotFound {
		// If no record was found, generate a new user ID and create the user
		user.UserId = uuid.New().String()
		if err := db.Db.SaveTx(&user); err != nil {
			return models.User{}, err
		}
		// Return the new user
		return db.GetUser(user.UserId)
	}
	return models.User{}, ErrUserExists
}

func (db *database) SetPublicKey(userId, pubKey string) error {
	value := models.User{PublicKey: pubKey}
	return db.Db.UpdateTx(value, "user_id = ?", userId)
}

func (db *database) UpdateTotp(enable bool, totp, userId string) error {
	value := models.User{
		TotpEnabled: enable,
		Totp:        totp,
	}
	return db.Db.UpdateTx(value, "user_id = ?", userId)
}

func (db *database) UpdateTokens(token, refreshToken, userId string) error {
	value := models.User{
		Token:        token,
		RefreshToken: refreshToken,
	}
	return db.Db.UpdateTx(value, "user_id = ?", userId)
}
