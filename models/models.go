package models

import (
	"database/sql"
	"log"

	_ "github.com/lib/pq"
)

var db *sql.DB

func InitDB() {
	var err error
	db, err = sql.Open("postgres", "user=postgres password=1234 dbname=postgres sslmode=disable")
	if err != nil {
		log.Fatal("Ошибка подключения к базе данных:", err)
	}
}

func CreateUser(login, password string) error {
	_, err := db.Exec("INSERT INTO users (login, password) VALUES ($1, $2)", login, password)
	return err
}

func GetUserIDByLogin(login string) int {
	var userID int
	err := db.QueryRow("SELECT id FROM users WHERE login = $1", login).Scan(&userID)
	if err != nil {
		return 0
	}
	return userID
}

func GetUserNameByID(userID int) (string, error) {
	var userName string
	err := db.QueryRow("SELECT login FROM users WHERE id = $1", userID).Scan(&userName)
	if err != nil {
		return "", err
	}
	return userName, nil
}

func StoreRefreshToken(userID, refreshTokenHash, ip string) error {
	_, err := db.Exec("INSERT INTO refresh_tokens (user_id, token_hash, ip) VALUES ($1, $2, $3)", userID, refreshTokenHash, ip)
	return err
}

func GetRefreshTokenInfo(refreshToken string) (userID, tokenHash, ip string, err error) {
	err = db.QueryRow("SELECT user_id, token_hash, ip FROM refresh_tokens WHERE token_hash=$1", refreshToken).Scan(&userID, &tokenHash, &ip)
	return
}

func UpdateRefreshToken(userID, newRefreshTokenHash, ip string) error {
	_, err := db.Exec("UPDATE refresh_tokens SET token_hash=$1, ip=$2 WHERE user_id=$3", newRefreshTokenHash, ip, userID)
	return err
}
