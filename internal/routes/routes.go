package routes

import (
	database "Auth_Service/internal/db"
	"Auth_Service/internal/models"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/smtp"
	"os"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

type Payload struct {
	ID        uuid.UUID `json:"id"`
	IssuedAt  time.Time `json:"issued_at"`
	ExpiredAt time.Time `json:"expired_at"`
	IP        string    `json:"ip"`
}

type RequestBody struct {
	RefreshToken string `json:"refresh_token"`
}

// creating tokens
func GetToken(w http.ResponseWriter, r *http.Request) {
	userIDStr := mux.Vars(r)["userID"]
	ip := r.RemoteAddr
	userIDStr = strings.TrimSpace(userIDStr)
	log.Printf("Get request with userid: %s and ip:%s", userIDStr, ip)

	userID, err := uuid.Parse(userIDStr)
	log.Printf(" userid uuid: %s ", userID)
	if err != nil {
		http.Error(w, "Invalid user ID", http.StatusBadRequest)
		return
	}

	//check user in db
	db := database.GetDB()
	var existingToken models.Refresh_Tokens
	err = db.Where("user_id = ?", userID).First(&existingToken).Error
	if err == nil {

		http.Error(w, "User already has refresh token", http.StatusConflict)
		return
	}

	//access token
	accessToken, err := createAccessToken(userID, ip)
	if err != nil {
		http.Error(w, "Error creating access token", http.StatusInternalServerError)
		return
	}

	//  refresh token
	refreshToken, err := createRefreshToken(userID, ip)
	if err != nil {
		http.Error(w, "Error creating refresh token", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, `{"access_token": "%s", "refresh_token": "%s"}`, accessToken, refreshToken)
}

func Refresh_token(w http.ResponseWriter, r *http.Request) {
	log.Printf("refresh token endpoint..")
	var body RequestBody
	err := json.NewDecoder(r.Body).Decode(&body)
	if err != nil || body.RefreshToken == "" {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	log.Printf("Was take from user token : %s", body.RefreshToken)

	//to uuid
	decodedTokenBytes, err := base64.StdEncoding.DecodeString(body.RefreshToken)
	if err != nil {
		http.Error(w, "Invalid base64 token", http.StatusBadRequest)
		return
	}
	str_token_UUID := string(decodedTokenBytes)
	log.Printf("Decoded token UUID: %s", str_token_UUID)

	lookup := computeHMAC(str_token_UUID)

	db := database.GetDB()
	var matchedToken models.Refresh_Tokens

	err = db.Where("lookup_hash = ?", lookup).First(&matchedToken).Error
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			http.Error(w, "Refresh token not found", http.StatusUnauthorized)
		} else {
			http.Error(w, "Database error", http.StatusInternalServerError)
		}
		return
	}

	log.Printf("matchedToken.Refresh_token from db : %s", matchedToken.Refresh_token)

	if bcrypt.CompareHashAndPassword([]byte(matchedToken.Refresh_token), []byte(str_token_UUID)) != nil {
		http.Error(w, "Refresh token not valid", http.StatusUnauthorized)
		log.Printf("Token validation failed for UUID: %s", str_token_UUID)
		return
	}

	userID := matchedToken.UserID //take user id
	ip := r.RemoteAddr            //new ip on endpoint

	if ip != matchedToken.IP {
		log.Printf("[DEV] IP mismatch detected! Old IP: %s, New IP: %s. Email would be sent to user: %s .", matchedToken.IP, ip, ip)
		//ТК не работает реализации отправки писем я отключил эту часть
		/*
			err := sendEmail(matchedToken.UserID.String(), "IP Address Changed",
				fmt.Sprintf("Warning: Your IP address has changed during the refresh token operation. New IP: %s. Please contact us if it is not you.", ip))
			if err != nil {
				http.Error(w, "Error sending email", http.StatusInternalServerError)
				return
			}
		*/
	}

	accessToken, err := createAccessToken(userID, ip)
	if err != nil {
		http.Error(w, "Error creating access token", http.StatusInternalServerError)
		return
	}

	newRefreshToken, err := createRefreshToken(userID, ip)
	if err != nil {
		http.Error(w, "Error creating refresh token", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, `{"access_token": "%s", "refresh_token": "%s"}`, accessToken, newRefreshToken)
}

// generate Access TOKEN
func createAccessToken(userID uuid.UUID, ip string) (string, error) {
	secretKey := os.Getenv("JWT_SECRET_KEY")
	if secretKey == "" {
		log.Fatal("JWT_SECRET_KEY not set in .env file")
	}

	payload := Payload{
		ID:        userID,
		IssuedAt:  time.Now(),
		ExpiredAt: time.Now().Add(time.Hour), // Токен действителен 1 час
		IP:        ip,
	}

	claims := jwt.NewWithClaims(jwt.SigningMethodHS512, jwt.MapClaims{
		"id":  payload.ID.String(),
		"iat": payload.IssuedAt.Unix(),
		"exp": payload.ExpiredAt.Unix(),
		"ip":  payload.IP,
	})

	tokenString, err := claims.SignedString([]byte(secretKey))
	if err != nil {
		return "", err
	}

	return tokenString, nil
}

func computeHMAC(message string) string {
	hmacSecret := os.Getenv("HMAC_SECRET")
	if hmacSecret == "" {
		log.Fatal("HMAC_SECRET not set in .env file")
	}
	h := hmac.New(sha256.New, []byte(hmacSecret))
	h.Write([]byte(message))
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}

// generate refresh token send to db and return to user original uuid refresh token
func createRefreshToken(userID uuid.UUID, ip string) (string, error) {
	refresh_tokenUUID, err := uuid.NewRandom()
	if err != nil {
		return "", err
	}

	hashedToken, err := bcrypt.GenerateFromPassword([]byte(refresh_tokenUUID.String()), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	hmacHash := computeHMAC(refresh_tokenUUID.String())
	db := database.GetDB()

	//if already  we have user   do updating fields
	var existingToken models.Refresh_Tokens
	err = db.Where("user_id = ?", userID).First(&existingToken).Error

	if err == nil {
		existingToken.Refresh_token = string(hashedToken)
		existingToken.IP = ip
		existingToken.Lookup_hash = hmacHash
		existingToken.UpdatedAt = time.Now()

		// update
		if err := db.Save(&existingToken).Error; err != nil {
			log.Printf("ERROR with updating refresh token in db: %v\n", err)
			return "", err
		}

	} else {
		refreshToken := models.Refresh_Tokens{
			Refresh_token: string(hashedToken),
			UserID:        userID,
			IP:            ip,
			Lookup_hash:   hmacHash,
			CreatedAt:     time.Now(),
			UpdatedAt:     time.Now(),
		}

		if err := db.Create(&refreshToken).Error; err != nil {
			log.Printf("ERROR with saving refresh token to db: %v\n", err)
			return "", err
		}
	}
	return base64.StdEncoding.EncodeToString([]byte(refresh_tokenUUID.String())), nil
}

func sendEmail(to, subject, body string) error {
	log.Printf("send to email...")
	//example
	from := "Organization@mail.ru"   //  email
	password := "password"           // passw
	smtpServer := "smtp.example.com" // SMTP server
	smtpPort := "4675"               // port SMTP

	auth := smtp.PlainAuth("", from, password, smtpServer)

	// body
	message := []byte("To: " + to + "\r\n" +
		"Subject: " + subject + "\r\n" +
		"\r\n" +
		body)

	// send
	err := smtp.SendMail(smtpServer+":"+smtpPort, auth, from, []string{to}, message)
	return err
}
