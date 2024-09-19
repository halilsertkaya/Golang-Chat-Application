package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v5"

	_ "github.com/go-sql-driver/mysql"
)

// Secret key to sign tokens
var jwtKey = []byte("my_secret_key")

// Claims struct to define JWT payload
type Claims struct {
	Username string `json:"username"`
	jwt.RegisteredClaims
}

// db setting
var db *sql.DB

// / Message struct we've to set.
type Message struct {
	Status  string `json:"status"`
	Message string `json:"message"`
}

// / Token Expiry Times
const (
	AccessTokenExpiry  = 30 * time.Minute //access token time
	RefreshTokenExpiry = 30 * time.Minute //refresh token time
)

func initDB() {
	var err error
	dsn := "root:@tcp(localhost:3306)/golivechat"
	db, err = sql.Open("mysql", dsn)
	if err != nil {
		log.Fatal(err)
	}
	if err = db.Ping(); err != nil {
		log.Fatal(err)
	}

	fmt.Println("Connected to 'golivechat' db on localhost:3306")
}

// Easy Midware controlling.
func loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Printf("Request: %s %s", r.Method, r.URL.Path)
		next.ServeHTTP(w, r)
	})
}

// / Auth MIDWARE - 2nd STEP CONVERT FOR JWT.
func authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// bypass for login url.
		if r.URL.Path == "/login" {
			next.ServeHTTP(w, r)
			return
		}

		cookie, err := r.Cookie("token")
		if err != nil {
			if err == http.ErrNoCookie {
				http.Error(w, "Unauthorized1. No token provided", http.StatusUnauthorized)
				return
			}
			http.Error(w, "Bad Request, unable to retrieve token", http.StatusBadRequest)
			return
		}

		tokenStr := cookie.Value
		claims := &Claims{}
		// Parse JWT Token
		token, err := jwt.ParseWithClaims(tokenStr, claims, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("Invalid Signing Method")
			}
			return jwtKey, nil
		})

		if err != nil {
			if err == jwt.ErrSignatureInvalid {
				http.Error(w, "Unauthorized, Invalid token signature", http.StatusUnauthorized)
				return
			}
			http.Error(w, "Unauthorized2, token parsing error.", http.StatusUnauthorized)
			return
		}

		if !token.Valid {
			http.Error(w, "Unauthorized: Invalid Token.", http.StatusUnauthorized)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// / First login, create automatically refresh_token and storage it into DB.
func createOrUpdateRefreshToken(username string) (string, error) {
	expirationTime := time.Now().Add(RefreshTokenExpiry)
	claims := &Claims{
		Username: username,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expirationTime),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	refreshToken, err := token.SignedString(jwtKey)
	if err != nil {
		return "", err
	}
	// Delete old refresh tokens if exists
	_, err = db.Exec("DELETE FROM refresh_tokens WHERE username = ?", username)
	if err != nil {
		return "", err
	}

	// Insert new refresh token
	_, err = db.Exec("INSERT INTO refresh_tokens (username, token, expires_at) VALUES (?,?,?)", username, refreshToken, expirationTime)
	if err != nil {
		return "", err
	}

	return refreshToken, nil
}

// / Refresh token Handling.
func refreshTokenHandler(w http.ResponseWriter, r *http.Request) {
	var request struct {
		RefreshToken string `json:"refresh_token"`
	}

	err := json.NewDecoder(r.Body).Decode(&request)
	if err != nil {
		http.Error(w, "Invalid request payload", http.StatusBadRequest)
		return
	}

	// Refresh Token, must be check in DB TABLE
	var username string
	var expiresAt time.Time
	err = db.QueryRow("SELECT username, expires_at FROM refresh_tokens WHERE token = ?", request.RefreshToken).Scan(&username, &expiresAt)
	if err != nil {
		http.Error(w, "Invalid or expired refresh token", http.StatusUnauthorized)
		return
	}

	if time.Now().After(expiresAt) {
		http.Error(w, "Refresh token expired", http.StatusUnauthorized)
		return
	}

	// Create new access-token
	expirationTime := time.Now().Add(AccessTokenExpiry)
	claims := &Claims{
		Username: username,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expirationTime),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	newAccessToken, err := token.SignedString(jwtKey)
	if err != nil {
		http.Error(w, "Error creating a new access token", http.StatusInternalServerError)
		return
	}

	// Update or create a new refresh token
	newRefreshToken, err := createOrUpdateRefreshToken(username)
	if err != nil {
		http.Error(w, "Error creating or updateing refresh token", http.StatusInternalServerError)
		return
	}
	// Turn into new AccessToken
	response := map[string]string{
		"access_token":  newAccessToken,
		"refresh_token": newRefreshToken,
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// Login handler to generate JWT token
func loginHandler(w http.ResponseWriter, r *http.Request) {
	var credentials struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}

	err := json.NewDecoder(r.Body).Decode(&credentials)
	if err != nil {
		http.Error(w, "Invalid request payload", http.StatusBadRequest)
		return
	}

	//Stable username and password only for now:
	// Later we will set it calling from database
	if credentials.Username != "testuser" || credentials.Password != "password123" {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	// Generating token
	expirationTime := time.Now().Add(AccessTokenExpiry) // 5 Dakika
	claims := &Claims{
		Username: credentials.Username,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expirationTime),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(jwtKey)
	if err != nil {
		http.Error(w, "Error creating Web Token", http.StatusInternalServerError)
		return
	}

	refreshToken, err := createOrUpdateRefreshToken((credentials.Username))
	if err != nil {
		http.Error(w, "Error creating refresh token", http.StatusInternalServerError)
		return
	}

	// Convert JWT to User -> Send cookie
	http.SetCookie(w, &http.Cookie{
		Name:    "token",
		Value:   tokenString,
		Expires: expirationTime,
		Path:    "/",
	})

	// Refresh Token convert to JSON
	response := map[string]string{
		"access_token":  tokenString,
		"refresh_token": refreshToken,
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func helloHandler(w http.ResponseWriter, r *http.Request) {
	msg := Message{
		Status:  "success",
		Message: fmt.Sprintf("Merhaba, %s .", r.URL.Path[1:]),
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("specialauth", "testsaltplace")
	json.NewEncoder(w).Encode(msg)
}

func welcomeHandler(w http.ResponseWriter, r *http.Request) {
	msg := Message{
		Status:  "success",
		Message: "Welcome to the Go Server.",
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(msg)
}

func postHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Not a valid request method", http.StatusMethodNotAllowed)
		return
	}

	// Json okuyalım
	var data map[string]string
	err := json.NewDecoder(r.Body).Decode(&data)
	if err != nil {
		http.Error(w, "Not a valid JSON", http.StatusBadRequest)
		return
	}

	msg := Message{
		Status:  "success",
		Message: fmt.Sprintf("Value: %s", data["name"]),
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(msg)
}

// ///////// Get All Users informations. (/user)
func getUsersHandler(w http.ResponseWriter, r *http.Request) {
	rows, err := db.Query("SELECT id, name, email FROM users")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var users []map[string]interface{}
	for rows.Next() {
		var id int
		var name, email string
		if err := rows.Scan(&id, &name, &email); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		user := map[string]interface{}{
			"id":    id,
			"name":  name,
			"email": email,
		}
		users = append(users, user)
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(users)
}

// /////////////////////// MYSQL CRUD OPERATIONS
// ///////// MySQL Adding New User FUNC
func createUserHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Not a valid request method", http.StatusMethodNotAllowed)
		return
	}
	var user struct {
		Name  string `json:"name"`
		Email string `json:"email"`
	}

	err := json.NewDecoder(r.Body).Decode(&user)
	if err != nil {
		http.Error(w, "Invalid Input!", http.StatusBadRequest)
		return
	}

	result, err := db.Exec("INSERT INTO users (name, email) VALUES (?, ?)", user.Name, user.Email)
	if err != nil {
		http.Error(w, "Failed to creating a new user.", http.StatusInternalServerError)
		return
	}
	id, _ := result.LastInsertId()
	msg := Message{
		Status:  "success",
		Message: fmt.Sprintf("User created with ID: %d", id),
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(msg)
}

// ///////// MySQL Query Example FUNC
func getUserHandler(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	if id == "" {
		http.Error(w, "ID Required", http.StatusBadRequest)
		return
	}

	var user struct {
		ID    int    `json:"id"`
		Name  string `json:"name"`
		Email string `json:"email"`
	}

	err := db.QueryRow("SELECT id, name, email FROM users WHERE id = ?", id).Scan(&user.ID, &user.Name, &user.Email)
	if err != nil {
		fmt.Println("Query error:", err)
		http.Error(w, "User not found!", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(user)
}

// ///////// MySQL Updating User FUNC
func updateUserHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}
	var user struct {
		ID    int    `json:"id"`
		Name  string `json:"name"`
		Email string `json:"email"`
	}

	err := json.NewDecoder(r.Body).Decode(&user)
	if err != nil {
		http.Error(w, "Invalid input", http.StatusBadRequest)
		return
	}

	_, err = db.Exec("UPDATE users SET name = ?, email = ? WHERE id = ?", user.Name, user.Email, user.ID)
	if err != nil {
		fmt.Println(err)
		http.Error(w, "Failed to update user", http.StatusInternalServerError)
		return
	}

	msg := Message{
		Status:  "success",
		Message: fmt.Sprintf("User with ID %d has been updated.", user.ID),
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(msg)
}

// ///////// MySQL Deleting User FUNC

func deleteUserHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}

	id := r.URL.Query().Get("id")
	if id == "" {
		http.Error(w, "Missing ID", http.StatusBadRequest)
		return
	}

	_, err := db.Exec("DELETE FROM users WHERE id = ?", id)
	if err != nil {
		http.Error(w, "Failed to delete user", http.StatusInternalServerError)
		return
	}

	msg := Message{
		Status:  "success",
		Message: fmt.Sprintf("User with ID %s , has been deleted", id),
	}
	// Burada tekrar header set ediyoruz ve JSON encode yapıyoruz.
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(msg)
}

// ///////////////////////
// ///////////////////////
func main() {
	initDB() // starting to connect MySQL database.

	mux := http.NewServeMux()
	mux.HandleFunc("/login", loginHandler)          // Login route
	mux.HandleFunc("/refresh", refreshTokenHandler) // Refresh token route

	mux.HandleFunc("/hello", helloHandler)
	mux.HandleFunc("/welcome", welcomeHandler)
	mux.HandleFunc("/post", postHandler)
	// CRUD (2nd step only for authorized users. After JWT settings.)
	mux.Handle("/users", authMiddleware(http.HandlerFunc(getUsersHandler)))
	mux.Handle("/create", authMiddleware(http.HandlerFunc(createUserHandler)))
	mux.Handle("/user", authMiddleware(http.HandlerFunc(getUserHandler)))
	mux.Handle("/update", authMiddleware(http.HandlerFunc(updateUserHandler)))
	mux.Handle("/delete", authMiddleware(http.HandlerFunc(deleteUserHandler)))

	loggedMux := loggingMiddleware(mux)
	authMux := authMiddleware(loggedMux)

	fmt.Println("Server has been started. Port: 9999")
	http.ListenAndServe(":9999", authMux)

}

/// DB name : golivechat
/// default username : root
/// default password : BLANK.
/// default port : 3307
