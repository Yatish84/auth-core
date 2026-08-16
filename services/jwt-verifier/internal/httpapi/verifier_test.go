package httpapi

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/golang-jwt/jwt/v5"
)

func TestJWTVerifierAcceptsValidTokenAndRejectsRevokedFamily(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	kid := "test-key"
	jwksServer := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(response).Encode(map[string]any{"keys": []map[string]string{{
			"kty": "RSA", "use": "sig", "alg": "RS256", "kid": kid,
			"n": encodeBigInteger(privateKey.PublicKey.N),
			"e": encodeBigInteger(big.NewInt(int64(privateKey.PublicKey.E))),
		}}})
	}))
	defer jwksServer.Close()

	redisServer := miniredis.RunT(t)
	verifier, err := NewJWTVerifier(
		jwksServer.URL,
		"https://issuer.test",
		"grox-test",
		"redis://"+redisServer.Addr()+"/0",
		"test-hmac-material-long-enough",
	)
	if err != nil {
		t.Fatal(err)
	}
	defer verifier.Close()

	now := time.Now()
	claims := jwt.MapClaims{
		"iss": "https://issuer.test", "aud": "grox-test", "sub": "user-id",
		"sid": "session-id", "fid": "family-id", "jti": "jti-id",
		"client_type": "WEB", "amr": []string{"password", "mfa"},
		"wid": "organization-id", "wtype": "organization", "roles": []string{"VIEWER"},
		"iat": now.Unix(), "nbf": now.Unix(), "exp": now.Add(15 * time.Minute).Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = kid
	raw, err := token.SignedString(privateKey)
	if err != nil {
		t.Fatal(err)
	}

	verified, err := verifier.Verify(context.Background(), raw)
	if err != nil {
		t.Fatalf("expected valid token: %v", err)
	}
	if verified.UserID != "user-id" || verified.SessionID != "session-id" {
		t.Fatalf("unexpected claims: %#v", verified)
	}
	if verified.WorkspaceID != "organization-id" || len(verified.Roles) != 1 {
		t.Fatalf("unexpected workspace claims: %#v", verified)
	}

	organizationKey := verifier.organizationRedisKey("user-id", "organization-id")
	redisServer.Set(organizationKey, "9999999999")
	if _, err := verifier.Verify(context.Background(), raw); err == nil {
		t.Fatal("expected revoked organization scope to be rejected")
	}
	redisServer.Del(organizationKey)

	redisServer.Set(verifier.redisKey("auth:revocation:family", "family-id"), "1")
	if _, err := verifier.Verify(context.Background(), raw); err == nil {
		t.Fatal("expected revoked family to be rejected")
	}
}

func encodeBigInteger(value *big.Int) string {
	return base64.RawURLEncoding.EncodeToString(value.Bytes())
}
