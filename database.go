package main

import (
	"context"
	"time"

	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"go.mongodb.org/mongo-driver/mongo/readpref"
)

func connectToDb() (*mongo.Collection, func(), error) {
	client, err := mongo.NewClient(options.Client().ApplyURI(MongoURL))
	if err != nil {
		return nil, nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	err = client.Connect(ctx)
	if err != nil {
		return nil, nil, err
	}
	disconnect := func() {
		client.Disconnect(ctx)
	}
	err = client.Ping(ctx, readpref.Primary())
	if err != nil {
		return nil, nil, err
	}
	collection := client.Database("authservice-go").Collection("users")
	return collection, disconnect, nil
}
