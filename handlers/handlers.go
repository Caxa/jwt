package handlers

import (
	"encoding/json"
	"html/template"
	"jwt/jwt"
	"jwt/models"
	"log"
	"net/http"
	"strconv"

	"golang.org/x/crypto/bcrypt"
)

type TokenRequest struct {
	UserID string `json:"user_id"`
	IP     string `json:"ip"`
}

var (
	errorTmpl    = template.Must(template.ParseFiles("templates/error.html"))
	registerTmpl = template.Must(template.ParseFiles("templates/register.html"))
	mainTmpl     = template.Must(template.ParseFiles("templates/main.html"))
)

func GetTokenHandler(w http.ResponseWriter, r *http.Request) {
	var req TokenRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		renderError(w, "Неверный запрос")
		return
	}
	if req.UserID == "" || req.IP == "" {
		renderError(w, "Отсутствуют необходимые параметры")
		return
	}

	accessToken, err := jwt.GenerateAccessToken(req.UserID, req.IP)
	if err != nil {
		renderError(w, "Ошибка генерации токена")
		return
	}

	refreshToken, refreshTokenHash, err := jwt.GenerateRefreshToken()
	if err != nil {
		renderError(w, "Ошибка генерации токена")
		return
	}

	err = models.StoreRefreshToken(req.UserID, refreshTokenHash, req.IP)
	if err != nil {
		renderError(w, "Ошибка сохранения токена")
		return
	}

	response := map[string]string{
		"access_token":  accessToken,
		"refresh_token": refreshToken,
	}
	json.NewEncoder(w).Encode(response)
}

func RefreshTokenHandler(w http.ResponseWriter, r *http.Request) {
	var req struct {
		RefreshToken string `json:"refresh_token"`
		IP           string `json:"ip"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		renderError(w, "Неверный запрос")
		return
	}
	if req.RefreshToken == "" || req.IP == "" {
		renderError(w, "Отсутствуют необходимые параметры")
		return
	}

	userID, storedHash, storedIP, err := models.GetRefreshTokenInfo(req.RefreshToken)
	if err != nil {
		renderError(w, "Токен недействителен")
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(storedHash), []byte(req.RefreshToken)); err != nil {
		renderError(w, "Неверный токен")
		return
	}

	if req.IP != storedIP {
		log.Println("IP адрес изменился, отправляем предупреждение")
	}

	accessToken, err := jwt.GenerateAccessToken(userID, req.IP)
	if err != nil {
		renderError(w, "Ошибка генерации токена")
		return
	}

	newRefreshToken, newRefreshTokenHash, err := jwt.GenerateRefreshToken()
	if err != nil {
		renderError(w, "Ошибка генерации токена")
		return
	}

	err = models.UpdateRefreshToken(userID, newRefreshTokenHash, req.IP)
	if err != nil {
		renderError(w, "Ошибка обновления токена")
		return
	}

	response := map[string]string{
		"access_token":  accessToken,
		"refresh_token": newRefreshToken,
	}
	json.NewEncoder(w).Encode(response)
}

func RegisterHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == "POST" {
		err := r.ParseForm()
		if err != nil {
			renderError(w, "Ошибка при разборе формы")
			return
		}
		login := r.Form.Get("login")
		password := r.Form.Get("password")

		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
		if err != nil {
			renderError(w, "Ошибка при хешировании пароля")
			return
		}

		err = models.CreateUser(login, string(hashedPassword))
		if err != nil {
			renderError(w, "Ошибка при сохранении пользователя")
			return
		}

		userID := models.GetUserIDByLogin(login)
		if userID > 0 {
			http.Redirect(w, r, "/main?id="+strconv.Itoa(userID), http.StatusFound)
		} else {
			renderError(w, "Ошибка аутентификации")
		}
	} else {
		registerTmpl.ExecuteTemplate(w, "register.html", nil)
	}
}

func MainPageHandler(w http.ResponseWriter, r *http.Request) {
	userIDStr := r.URL.Query().Get("id")
	userID, err := strconv.Atoi(userIDStr)
	if err != nil {
		renderError(w, "Неверный идентификатор пользователя")
		return
	}

	userName, err := models.GetUserNameByID(userID)
	if err != nil {
		renderError(w, "Ошибка при получении имени пользователя")
		return
	}

	data := struct {
		UserName string
		UserID   int
	}{
		UserName: userName,
		UserID:   userID,
	}

	if err := mainTmpl.ExecuteTemplate(w, "main.html", data); err != nil {
		renderError(w, "Ошибка отображения страницы")
	}
}

func renderError(w http.ResponseWriter, message string) {
	data := struct {
		Message string
	}{
		Message: message,
	}
	if err := errorTmpl.ExecuteTemplate(w, "error.html", data); err != nil {
		http.Error(w, "Ошибка отображения страницы", http.StatusInternalServerError)
	}
}
