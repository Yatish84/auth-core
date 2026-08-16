package httpapi

import (
	"encoding/json"
	"net/http"
)

type healthResponse struct {
	Service string `json:"service"`
	Status  string `json:"status"`
}

func NewRouter(verifiers ...Verifier) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health/live", healthHandler("up"))
	mux.HandleFunc("GET /health/ready", healthHandler("ready"))
	if len(verifiers) > 0 && verifiers[0] != nil {
		mux.HandleFunc("GET /verify", verifyHandler(verifiers[0]))
	}
	return mux
}

func verifyHandler(verifier Verifier) http.HandlerFunc {
	return func(response http.ResponseWriter, request *http.Request) {
		authorization := request.Header.Get("Authorization")
		if len(authorization) < 8 || authorization[:7] != "Bearer " {
			writeProblem(response)
			return
		}
		claims, err := verifier.Verify(request.Context(), authorization[7:])
		if err != nil {
			writeProblem(response)
			return
		}
		response.Header().Set("Content-Type", "application/json")
		response.Header().Set("Cache-Control", "no-store")
		_ = json.NewEncoder(response).Encode(claims)
	}
}

func writeProblem(response http.ResponseWriter) {
	response.Header().Set("Content-Type", "application/problem+json")
	response.Header().Set("Cache-Control", "no-store")
	response.Header().Set("WWW-Authenticate", "Bearer")
	response.WriteHeader(http.StatusUnauthorized)
	_ = json.NewEncoder(response).Encode(map[string]any{
		"title":  "Access token rejected",
		"status": http.StatusUnauthorized,
		"code":   "AUTH_TOKEN_INVALID",
	})
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
