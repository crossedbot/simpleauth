package database

import (
	"context"
	"strings"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"

	"github.com/crossedbot/simpleauth/pkg/models"
)

type mongodb struct {
	Ctx  context.Context
	Path string
	Db   *mongo.Client
}

func NewMongoDB(ctx context.Context, path string) (Database, error) {
	client, err := mongo.NewClient(options.Client().ApplyURI(path))
	if err != nil {
		return nil, err
	}
	if err := client.Connect(ctx); err != nil {
		return nil, err
	}
	return &mongodb{
		Ctx:  ctx,
		Path: path,
		Db:   client,
	}, nil
}

func (db *mongodb) GetUser(id string) (models.User, error) {
	users := db.Users()
	filter := bson.M{"user_id": id}
	var user models.User
	if err := users.FindOne(db.Ctx, filter).Decode(&user); err != nil {
		return models.User{}, err
	}
	return user, nil
}

func (db *mongodb) GetUserByName(name string) (models.User, error) {
	name = strings.ToLower(name)
	users := db.Users()
	filter := bson.D{bson.E{
		Key: "$or",
		Value: bson.A{
			bson.M{"email": name},
			bson.M{"username": name},
		},
	}}
	var user models.User
	if err := users.FindOne(db.Ctx, filter).Decode(&user); err != nil {
		return models.User{}, err
	}
	return user, nil
}

func (db *mongodb) SaveUser(user models.User) (models.User, error) {
	user.Username = strings.ToLower(user.Username)
	user.Email = strings.ToLower(user.Email)
	params := bson.A{bson.M{"username": user.Username}}
	if user.Email != "" {
		params = append(params, bson.M{"email": user.Email})
	}
	filter := bson.D{bson.E{Key: "$or", Value: params}}
	userCount, err := db.Users().CountDocuments(db.Ctx, filter)
	if err != nil {
		return models.User{}, err
	}
	if user.Phone != "" {
		count, err := db.Users().CountDocuments(
			db.Ctx,
			bson.M{"phone": user.Phone},
		)
		if err != nil {
			return models.User{}, err
		}
		userCount += count
	}
	if userCount > 0 {
		return models.User{}, ErrUserExists
	}
	user.ObjectId = primitive.NewObjectID()
	user.UserId = user.ObjectId.Hex()
	if _, err := db.Users().InsertOne(db.Ctx, user); err != nil {
		return models.User{}, err
	}
	return db.GetUser(user.UserId)
}

func (db *mongodb) UpdateTotp(enable bool, totp, userId string) error {
	users := db.Users()
	now, _ := time.Parse(time.RFC3339, time.Now().Format(time.RFC3339))
	update := primitive.D{
		bson.E{Key: "totp_enabled", Value: enable},
		bson.E{Key: "totp", Value: totp},
		bson.E{Key: "updated_at", Value: now},
	}
	upsert := true
	_, err := users.UpdateOne(
		db.Ctx,
		bson.M{"user_id": userId},
		bson.D{bson.E{Key: "$set", Value: update}},
		&options.UpdateOptions{Upsert: &upsert},
	)
	return err
}

func (db *mongodb) UpdateTokens(token, refreshToken, userId string) error {
	users := db.Users()
	now, _ := time.Parse(time.RFC3339, time.Now().Format(time.RFC3339))
	update := primitive.D{
		bson.E{Key: "token", Value: token},
		bson.E{Key: "refresh_token", Value: refreshToken},
		bson.E{Key: "updated_at", Value: now},
	}
	upsert := true
	_, err := users.UpdateOne(
		db.Ctx,
		bson.M{"user_id": userId},
		bson.D{bson.E{Key: "$set", Value: update}},
		&options.UpdateOptions{Upsert: &upsert},
	)
	return err
}

func (db *mongodb) Users() *mongo.Collection {
	return db.Db.Database("auth").Collection("users")
}
