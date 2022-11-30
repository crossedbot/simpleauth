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
	DialectMongoDb   = "mongodb"
	DialectMySQL     = "mysql"
	DialectPostgres  = "prostgres"
	DialectSqlite3   = "sqlite3"
	DialectSqlServer = "sqlserver"
)

var (
	ErrUserExists = errors.New("The username, email or phone number already exists")
)

type Database interface {
	GetUser(id string) (models.User, error)

	GetUserByName(name string) (models.User, error)

	SaveUser(user models.User) (models.User, error)

	UpdateTotp(enable bool, totp, userId string) error

	UpdateTokens(token, refreshToken, userId string) error
}

type database struct {
	Ctx     context.Context
	Dialect string
	Path    string
	Db      cdb.Database
}

func New(ctx context.Context, dialect, path string) (Database, error) {
	dialect = strings.ToLower(dialect)
	if dialect == DialectMongoDb {
		return NewMongoDB(ctx, path)
	}
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
		// Create the user if no record was found
		user.UserId = uuid.New().String()
		if err := db.Db.SaveTx(&user); err != nil {
			return models.User{}, err
		}
		return db.GetUser(user.UserId)
	}
	return models.User{}, ErrUserExists
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
