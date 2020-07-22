package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/dgrijalva/jwt-go"
	"github.com/labstack/echo"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo/options"
	"golang.org/x/crypto/bcrypt"
)

type handler struct{}

//Model of user
type Model struct {
	ID     primitive.ObjectID `bson:"_id,omitempty"`
	Tokens []TokenPairs       `bson:"tokens,omitempty"`
}

//TokenPairs of user
type TokenPairs struct {
	AccessToken  string `bson:"accessToken,omitempty"`
	RefreshToken string `bson:"refreshToken,omitempty"`
}

type tokenReqBody struct {
	AccessToken  string `json:"accessToken"`
	RefreshToken string `json:"refreshToken"`
}

var MongoURL = os.Getenv("MONGO_URL")

// Контроллер маршрута выдачи токенов
func (h *handler) login(c echo.Context) error {
	ID := c.QueryParam("ID")
	userID, err := primitive.ObjectIDFromHex(ID)
	if err != nil {
		log.Println("Invalid ObjectID")
	}
	// Подключение к БД
	collection, disconnect, err := connectToDb()
	defer disconnect()
	if err != nil {
		log.Fatal(err)
	}
	// Поиск пользователя в БД
	var result Model
	filter := bson.D{{"_id", userID}}
	err = collection.FindOne(context.TODO(), filter).Decode(&result)
	if err != nil {
		log.Fatal(err)
	}
	// Генерация пары токенов
	tokens, err := generateTokenPair(result)
	if err != nil {
		return err
	}
	// Хеширование и добавление токенов в БД
	defer func(t map[string]string) {
		hash, err := bcrypt.GenerateFromPassword([]byte(t["refreshToken"]), 8)
		t["refreshToken"] = string(hash)
		update := bson.D{{"$push", bson.D{{"tokens", t}}}}
		result, err := collection.UpdateOne(context.TODO(), filter, update)
		if err != nil {
			log.Fatal(err)
		}
		if result.MatchedCount != 0 {
			fmt.Println("matched and replaced an existing document")
		}
		if result.UpsertedCount != 0 {
			fmt.Printf("inserted a new document with ID %v\n", result.UpsertedID)
		}
	}(tokens)

	return c.JSON(http.StatusOK, tokens)
}

// Контроллер маршрута обновления токенов
func (h *handler) token(c echo.Context) error {
	// Присвоение токенов переменной
	tokenReq := tokenReqBody{}
	c.Bind(&tokenReq)
	// Проверка access токена
	token, err := jwt.Parse(tokenReq.AccessToken, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}
		return []byte("secret"), nil
	})
	// Проверка refresh токена
	refToken, err := jwt.Parse(tokenReq.RefreshToken, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}
		return []byte("secret"), nil
	})

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		if refClaims, ok := refToken.Claims.(jwt.MapClaims); ok && refToken.Valid && claims["refId"] == refClaims["id"] {
			// Подключение к БД
			collection, disconnect, err := connectToDb()
			defer disconnect()
			if err != nil {
				log.Fatal(err)
			}
			// Поиск пользователя в БД
			var result Model
			filter := bson.D{{"tokens", bson.M{"$elemMatch": bson.D{{"accessToken", tokenReq.AccessToken}}}}}
			projection := options.FindOne().SetProjection(bson.D{{"tokens", bson.M{"$elemMatch": bson.D{{"accessToken", tokenReq.AccessToken}}}}})
			err = collection.FindOne(context.TODO(), filter, projection).Decode(&result)
			if err != nil {
				log.Fatal(err)
			}
			// Сверка с хешированным рефреш токеном
			err = bcrypt.CompareHashAndPassword([]byte(result.Tokens[0].RefreshToken), []byte(tokenReq.RefreshToken))
			if err != nil {
				log.Fatal(err)
			}
			// Проверка пользователя и генерация новой пары токенов
			if claims["userId"] == result.ID.Hex() {
				newTokenPair, err := generateTokenPair(result)
				if err != nil {
					return err
				}
				// Хеширование токена и замена старых в БД
				defer func(t map[string]string) {
					hash, err := bcrypt.GenerateFromPassword([]byte(t["refreshToken"]), 8)
					update := bson.D{
						{"$set", bson.D{
							{"tokens.$[elem].accessToken", t["accessToken"]},
							{"tokens.$[elem].refreshToken", string(hash)},
						}},
					}
					options := options.Update().SetArrayFilters(options.ArrayFilters{
						Filters: []interface{}{bson.D{
							{"elem.accessToken", tokenReq.AccessToken},
						}},
					})
					result, err := collection.UpdateOne(context.TODO(), filter, update, options)
					if err != nil {
						log.Fatal(err)
					}
					if result.MatchedCount != 0 {
						fmt.Println("matched and replaced an existing document")
					}
					if result.UpsertedCount != 0 {
						fmt.Printf("inserted a new document with ID %v\n", result.UpsertedID)
					}
				}(newTokenPair)

				return c.JSON(http.StatusOK, newTokenPair)
			}
			return echo.ErrUnauthorized
		}
	}
	return err
}

// Контроллер маршрута удаления рефреш токена
func (h *handler) remove(c echo.Context) error {
	tokenReq := tokenReqBody{}
	c.Bind(&tokenReq)

	token, err := jwt.Parse(tokenReq.AccessToken, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}
		return []byte("secret"), nil
	})

	refToken, err := jwt.Parse(tokenReq.RefreshToken, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}
		return []byte("secret"), nil
	})

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		if refClaims, ok := refToken.Claims.(jwt.MapClaims); ok && refToken.Valid && claims["refId"] == refClaims["id"] {

			collection, disconnect, err := connectToDb()
			defer disconnect()
			if err != nil {
				log.Fatal(err)
			}

			var result Model
			filter := bson.D{{"tokens", bson.M{"$elemMatch": bson.D{{"accessToken", tokenReq.AccessToken}}}}}
			projection := options.FindOne().SetProjection(bson.D{{"tokens", bson.M{"$elemMatch": bson.D{{"accessToken", tokenReq.AccessToken}}}}})
			err = collection.FindOne(context.TODO(), filter, projection).Decode(&result)
			if err != nil {
				log.Fatal(err)
			}

			err = bcrypt.CompareHashAndPassword([]byte(result.Tokens[0].RefreshToken), []byte(tokenReq.RefreshToken))
			if err != nil {
				log.Fatal(err)
			}

			if claims["userId"] == result.ID.Hex() {
				update := bson.D{
					{"$set", bson.D{
						{"tokens.$[elem].refreshToken", ""},
					}},
				}
				options := options.Update().SetArrayFilters(options.ArrayFilters{
					Filters: []interface{}{bson.D{
						{"elem.accessToken", tokenReq.AccessToken},
					}},
				})
				result, err := collection.UpdateOne(context.TODO(), filter, update, options)
				if err != nil {
					log.Fatal(err)
				}
				if result.MatchedCount != 0 {
					fmt.Println("matched and replaced an existing document")
				}
				if result.UpsertedCount != 0 {
					fmt.Printf("inserted a new document with ID %v\n", result.UpsertedID)
				}
				return c.JSON(http.StatusOK, result)
			}
			return echo.ErrUnauthorized
		}
	}
	return err
}

func (h *handler) removeAll(c echo.Context) error {
	tokenReq := tokenReqBody{}
	c.Bind(&tokenReq)

	token, err := jwt.Parse(tokenReq.AccessToken, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}
		return []byte("secret"), nil
	})

	refToken, err := jwt.Parse(tokenReq.RefreshToken, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}
		return []byte("secret"), nil
	})

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		if refClaims, ok := refToken.Claims.(jwt.MapClaims); ok && refToken.Valid && claims["refId"] == refClaims["id"] {

			collection, disconnect, err := connectToDb()
			defer disconnect()
			if err != nil {
				log.Fatal(err)
			}

			var result Model
			filter := bson.D{{"tokens", bson.M{"$elemMatch": bson.D{{"accessToken", tokenReq.AccessToken}}}}}
			projection := options.FindOne().SetProjection(bson.D{{"tokens", bson.M{"$elemMatch": bson.D{{"accessToken", tokenReq.AccessToken}}}}})
			err = collection.FindOne(context.TODO(), filter, projection).Decode(&result)
			if err != nil {
				log.Fatal(err)
			}

			err = bcrypt.CompareHashAndPassword([]byte(result.Tokens[0].RefreshToken), []byte(tokenReq.RefreshToken))
			if err != nil {
				log.Fatal(err)
			}

			if claims["userId"] == result.ID.Hex() {
				update := bson.D{{"$set", bson.D{{"tokens", bson.A{}}}}}
				result1, err := collection.UpdateOne(context.TODO(), filter, update)
				if err != nil {
					log.Fatal(err)
				}
				if result1.MatchedCount != 0 {
					fmt.Println("matched and replaced an existing document")
				}
				if result1.UpsertedCount != 0 {
					fmt.Printf("inserted a new document with ID %v\n", result1.UpsertedID)
				}
				return c.JSON(http.StatusOK, "All tokens have been removed")
			}
			return echo.ErrUnauthorized
		}
	}
	return err
}
