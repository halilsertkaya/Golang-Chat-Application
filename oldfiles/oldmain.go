package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
)

// db setting
var db *sql.DB

// / Daha önceki gibi message struct'ı tanımlıyoruz.
type Message struct {
	Status  string `json:"status"`
	Message string `json:"message"`
}

// Basit bir log middleware yazalım.
func loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Printf("Request: %s %s", r.Method, r.URL.Path)
		next.ServeHTTP(w, r)
	})
}

func helloHandler(w http.ResponseWriter, r *http.Request) {
	msg := Message{
		Status:  "success",
		Message: fmt.Sprintf("Merhaba, %s .", r.URL.Path[1:]),
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("code", "testcustomgateway")
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

// / Auth Midware ekleyelim.
func authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := r.Header.Get("Authorization")
		if token != "test2" {
			http.Error(w, "Forbidden Access", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// Main FUNC
func main() {
	mux := http.NewServeMux()
	mux.HandleFunc("/hello", helloHandler)
	mux.HandleFunc("/welcome", welcomeHandler)
	mux.HandleFunc("/post", postHandler)
	/// Midware main handler içerisinde sarıyoruz.
	loggedMux := loggingMiddleware(mux)
	authMux := authMiddleware(loggedMux)

	fmt.Println("Server started. Port: 9999")
	http.ListenAndServe(":9999", authMux)
}
