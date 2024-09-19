package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestLoginHandler(t *testing.T) {
	req, err := http.NewRequest(http.MethodPost, "/login", nil)
	if err != nil {
		t.Fatalf("couldn't create request: %v", err)
	}
	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(loginHandler)
	handler.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusOK {
		t.Errorf("handler returned wrong status code got %v want %v", status, http.StatusOK)
	}
}
