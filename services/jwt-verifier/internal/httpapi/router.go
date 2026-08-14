package httpapi

import (
	"encoding/json"
	"net/http"
)

type healthResponse struct {
	Service string `json:"service"`
	Status  string `json:"status"`
}

func NewRouter() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health/live", healthHandler("up"))
	mux.HandleFunc("GET /health/ready", healthHandler("ready"))
	return mux
}

func healthHandler(status string) http.HandlerFunc {
	return func(response http.ResponseWriter, _ *http.Request) {
		response.Header().Set("Content-Type", "application/json")
		response.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(response).Encode(healthResponse{
			Service: "auth-core-jwt-verifier",
			Status:  status,
		})
	}
}
