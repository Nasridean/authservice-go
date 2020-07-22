package main

import (
	"github.com/dgrijalva/jwt-go"
	"github.com/google/uuid"
)

func generateTokenPair(r Model) (map[string]string, error) {
	// Создание access токена
	token := jwt.New(jwt.SigningMethodHS512)
	refID := uuid.New()

	// Присвоение payload
	claims := token.Claims.(jwt.MapClaims)
	claims["id"] = uuid.New()
	claims["userId"] = r.ID
	claims["refId"] = refID
	claims["type"] = "access"

	// Подписание токена.
	t, err := token.SignedString([]byte("secret"))
	if err != nil {
		return nil, err
	}
	// Создание refresh токена и присвоение payload
	refreshToken := jwt.New(jwt.SigningMethodHS512)
	rtClaims := refreshToken.Claims.(jwt.MapClaims)
	rtClaims["id"] = refID
	rtClaims["type"] = "refresh"
	// Подписание токена.
	rt, err := refreshToken.SignedString([]byte("secret"))
	if err != nil {
		return nil, err
	}
	// Возращение готовых токенов
	return map[string]string{
		"accessToken":  t,
		"refreshToken": rt,
	}, nil
}
