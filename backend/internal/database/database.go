package database

import (
	"context"
	"log/slog"
	"time"

	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

var DB *MongoDB

type MongoDB struct {
	Client     *mongo.Client
	Database   *mongo.Database
	Collection *mongo.Collection
}

func ConnectToMongoDB(uri, dbName string) error {
	clientOptions := options.Client().ApplyURI(uri)
	client, err := mongo.Connect(context.TODO(), clientOptions)
	if err != nil {
		slog.Error("MongoDB connection failed.", "err", err)
		return err
	}

	err = client.Ping(context.TODO(), nil)
	if err != nil {
		slog.Error("MongoDB ping failed.", "err", err)
		return err
	}

	slog.Info("MongoDB successfully connected", "uri", uri)

	DB = &MongoDB{
		Client:   client,
		Database: client.Database(dbName),
	}
	return nil
}

func (m *MongoDB) SetCollection(collectionName string) {
	m.Collection = m.Database.Collection(collectionName)
	slog.Debug("Collection changed.", "collection", collectionName)
}

func (m *MongoDB) InsertOne(data interface{}) (*mongo.InsertOneResult, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	result, err := m.Collection.InsertOne(ctx, data)
	if err != nil {
		slog.Debug("Failed to insert", "err", err)
		return nil, err
	}
	slog.Debug("Insert succeeded", "inserted_id", result.InsertedID)
	return result, nil
}

func (m *MongoDB) FindOne(filter interface{}, result interface{}) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err := m.Collection.FindOne(ctx, filter).Decode(result)
	if err != nil {
		slog.Debug("Not found.", "err", err)
		return err
	}
	slog.Debug("Object found.", "result", result)
	return nil
}

func (m *MongoDB) FindAll(filter interface{}, result interface{}) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cursor, err := m.Collection.Find(ctx, filter)
	if err != nil {
		slog.Debug("Find failed.", "err", err)
		return err
	}
	defer cursor.Close(ctx)
	err = cursor.All(ctx, result)
	if err != nil {
		slog.Debug("Cursor failed.", "err", err)
		return err
	}
	slog.Debug("Successfully found.", "result", result)
	return nil
}

func (m *MongoDB) FindWithProjection(filter interface{}, projection interface{}, result interface{}) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	findOptions := options.Find()
	if projection != nil {
		findOptions.SetProjection(projection)
	}

	cursor, err := m.Collection.Find(ctx, filter, findOptions)
	if err != nil {
		slog.Debug("Find failed.", "err", err)
		return err
	}
	defer cursor.Close(ctx)

	err = cursor.All(ctx, result)
	if err != nil {
		slog.Debug("Cursor failed.", "err", err)
		return err
	}
	slog.Debug("Successfully found.", "result", result)
	return nil
}

func (m *MongoDB) UpdateOne(filter, update interface{}) (*mongo.UpdateResult, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	result, err := m.Collection.UpdateOne(ctx, filter, update)
	if err != nil {
		slog.Debug("Update failed.", "err", err)
		return nil, err
	}
	slog.Debug("Successfully updated.", "modified_count", result.ModifiedCount)
	return result, nil
}

func (m *MongoDB) DeleteOne(filter interface{}) (*mongo.DeleteResult, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	result, err := m.Collection.DeleteOne(ctx, filter)
	if err != nil {
		slog.Debug("Deletion failed.", "err", err)
		return nil, err
	}
	slog.Debug("Deleted successfully.", "deleted_count", result.DeletedCount)
	return result, nil
}
