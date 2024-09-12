package main

import (
	"jwt/handlers"
	"jwt/models"
	"log"
	"net/http"
)

func main() {

	models.InitDB()

	http.HandleFunc("/", handlers.RegisterHandler)
	http.HandleFunc("/auth/token", handlers.GetTokenHandler)
	http.HandleFunc("/auth/refresh", handlers.RefreshTokenHandler)
	http.HandleFunc("/main", handlers.MainPageHandler)

	log.Println("Сервер запущен на :8080")
	if err := http.ListenAndServe(":8080", nil); err != nil {
		log.Fatal("Ошибка запуска сервера:", err)
	}
}
