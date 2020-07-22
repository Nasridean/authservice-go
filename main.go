package main

import (
	"log"
	"net/http"
	"os"

	"github.com/joho/godotenv"
	"github.com/labstack/echo"
)

func init() {
	if err := godotenv.Load("database.env"); err != nil {
		log.Print("No .env file found")
	}
}

func main() {
	e := echo.New()
	e.GET("/", func(c echo.Context) error {
		return c.String(http.StatusOK, "Hello, World!")
	})

	h := &handler{}
	port := os.Getenv("PORT")

	e.GET("/login", h.login)

	e.POST("/remove", h.remove)

	e.POST("/removeAll", h.removeAll)

	e.POST("/token", h.token)

	e.Logger.Fatal(e.Start(":" + port))
}
