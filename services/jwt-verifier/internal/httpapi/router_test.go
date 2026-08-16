package httpapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type fakeVerifier struct{}

func (fakeVerifier) Verify(context.Context, string) (VerifiedClaims, error) {
	return VerifiedClaims{UserID: "user", SessionID: "session"}, nil
}

func TestLiveness(t *testing.T) {
	request := httptest.NewRequest(http.MethodGet, "/health/live", nil)
	recorder := httptest.NewRecorder()

	NewRouter().ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d", http.StatusOK, recorder.Code)
	}
	if !strings.Contains(recorder.Body.String(), `"status":"up"`) {
		t.Fatalf("expected up response, got %s", recorder.Body.String())
	}
}

func TestVerifyBoundaryReturnsSafeClaims(t *testing.T) {
	request := httptest.NewRequest(http.MethodGet, "/verify", nil)
	request.Header.Set("Authorization", "Bearer signed-token")
	recorder := httptest.NewRecorder()

	NewRouter(fakeVerifier{}).ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d", http.StatusOK, recorder.Code)
	}
	if !strings.Contains(recorder.Body.String(), `"user_id":"user"`) {
		t.Fatalf("expected verified claims, got %s", recorder.Body.String())
	}
}
