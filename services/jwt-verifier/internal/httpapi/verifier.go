package httpapi

import (
	"context"
	"crypto/hmac"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/redis/go-redis/v9"
)

var ErrTokenInvalid = errors.New("token invalid")

type VerifiedClaims struct {
	UserID        string   `json:"user_id"`
	SessionID     string   `json:"session_id"`
	FamilyID      string   `json:"family_id"`
	JTI           string   `json:"jti"`
	ClientType    string   `json:"client_type"`
	Assurance     []string `json:"assurance"`
	WorkspaceID   string   `json:"workspace_id,omitempty"`
	WorkspaceType string   `json:"workspace_type,omitempty"`
	Roles         []string `json:"roles,omitempty"`
	IssuedAt      time.Time
}

type Verifier interface {
	Verify(context.Context, string) (VerifiedClaims, error)
}

type JWTVerifier struct {
	jwksURL    string
	issuer     string
	audience   string
	redis      *redis.Client
	hmacSecret []byte
	client     *http.Client
	mutex      sync.RWMutex
	keys       map[string]*rsa.PublicKey
	keysUntil  time.Time
}

type jwksDocument struct {
	Keys []jwk `json:"keys"`
}

type jwk struct {
	KID string `json:"kid"`
	Kty string `json:"kty"`
	N   string `json:"n"`
	E   string `json:"e"`
}

func NewJWTVerifier(
	jwksURL string,
	issuer string,
	audience string,
	redisURL string,
	hmacSecret string,
) (*JWTVerifier, error) {
	options, err := redis.ParseURL(redisURL)
	if err != nil {
		return nil, fmt.Errorf("parse redis URL: %w", err)
	}
	if len(hmacSecret) < 16 {
		return nil, errors.New("redis HMAC secret must contain at least 16 bytes")
	}
	return &JWTVerifier{
		jwksURL:    jwksURL,
		issuer:     issuer,
		audience:   audience,
		redis:      redis.NewClient(options),
		hmacSecret: []byte(hmacSecret),
		client:     &http.Client{Timeout: 2 * time.Second},
		keys:       make(map[string]*rsa.PublicKey),
	}, nil
}

func (verifier *JWTVerifier) Verify(ctx context.Context, raw string) (VerifiedClaims, error) {
	parsed, err := jwt.Parse(
		raw,
		func(token *jwt.Token) (any, error) {
			kid, ok := token.Header["kid"].(string)
			if !ok || kid == "" {
				return nil, ErrTokenInvalid
			}
			return verifier.key(ctx, kid)
		},
		jwt.WithValidMethods([]string{"RS256"}),
		jwt.WithIssuer(verifier.issuer),
		jwt.WithAudience(verifier.audience),
		jwt.WithExpirationRequired(),
		jwt.WithIssuedAt(),
	)
	if err != nil || !parsed.Valid {
		return VerifiedClaims{}, ErrTokenInvalid
	}
	claims, ok := parsed.Claims.(jwt.MapClaims)
	if !ok {
		return VerifiedClaims{}, ErrTokenInvalid
	}
	verified, err := verifiedClaims(claims)
	if err != nil {
		return VerifiedClaims{}, err
	}
	if err := verifier.checkRevocation(ctx, verified); err != nil {
		return VerifiedClaims{}, err
	}
	return verified, nil
}

func (verifier *JWTVerifier) Close() error {
	return verifier.redis.Close()
}

func (verifier *JWTVerifier) key(ctx context.Context, kid string) (*rsa.PublicKey, error) {
	verifier.mutex.RLock()
	key := verifier.keys[kid]
	valid := time.Now().Before(verifier.keysUntil)
	verifier.mutex.RUnlock()
	if key != nil && valid {
		return key, nil
	}
	if err := verifier.refreshKeys(ctx); err != nil {
		return nil, err
	}
	verifier.mutex.RLock()
	defer verifier.mutex.RUnlock()
	key = verifier.keys[kid]
	if key == nil {
		return nil, ErrTokenInvalid
	}
	return key, nil
}

func (verifier *JWTVerifier) refreshKeys(ctx context.Context) error {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, verifier.jwksURL, nil)
	if err != nil {
		return err
	}
	response, err := verifier.client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("JWKS returned %d", response.StatusCode)
	}
	var document jwksDocument
	if err := json.NewDecoder(response.Body).Decode(&document); err != nil {
		return err
	}
	keys := make(map[string]*rsa.PublicKey, len(document.Keys))
	for _, value := range document.Keys {
		if value.Kty != "RSA" || value.KID == "" {
			continue
		}
		modulus, err := base64.RawURLEncoding.DecodeString(value.N)
		if err != nil {
			return err
		}
		exponentBytes, err := base64.RawURLEncoding.DecodeString(value.E)
		if err != nil {
			return err
		}
		exponent := new(big.Int).SetBytes(exponentBytes)
		if !exponent.IsInt64() {
			return ErrTokenInvalid
		}
		keys[value.KID] = &rsa.PublicKey{N: new(big.Int).SetBytes(modulus), E: int(exponent.Int64())}
	}
	verifier.mutex.Lock()
	verifier.keys = keys
	verifier.keysUntil = time.Now().Add(5 * time.Minute)
	verifier.mutex.Unlock()
	return nil
}

func (verifier *JWTVerifier) checkRevocation(
	ctx context.Context, claims VerifiedClaims,
) error {
	keys := []string{
		verifier.redisKey("auth:revocation:jti", claims.JTI),
		verifier.redisKey("auth:revocation:family", claims.FamilyID),
		verifier.redisKey("auth:revocation:user", claims.UserID),
	}
	if claims.WorkspaceID != "" && claims.WorkspaceType == "organization" {
		keys = append(keys, verifier.organizationRedisKey(claims.UserID, claims.WorkspaceID))
	}
	values, err := verifier.redis.MGet(ctx, keys...).Result()
	if err != nil {
		return err
	}
	if values[0] != nil || values[1] != nil {
		return ErrTokenInvalid
	}
	if value, ok := values[2].(string); ok {
		var revokedAt int64
		if _, err := fmt.Sscan(value, &revokedAt); err != nil {
			return ErrTokenInvalid
		}
		if claims.IssuedAt.Unix() <= revokedAt {
			return ErrTokenInvalid
		}
	}
	if len(values) == 4 {
		if value, ok := values[3].(string); ok {
			var revokedAt int64
			if _, err := fmt.Sscan(value, &revokedAt); err != nil {
				return ErrTokenInvalid
			}
			if claims.IssuedAt.Unix() <= revokedAt {
				return ErrTokenInvalid
			}
		}
	}
	return nil
}

func (verifier *JWTVerifier) redisKey(prefix string, value string) string {
	return prefix + ":" + verifier.opaque(value)
}

func (verifier *JWTVerifier) organizationRedisKey(userID string, workspaceID string) string {
	return "auth:revocation:org:" + verifier.opaque(userID) + ":" + verifier.opaque(workspaceID)
}

func (verifier *JWTVerifier) opaque(value string) string {
	digest := hmac.New(sha256.New, verifier.hmacSecret)
	_, _ = digest.Write([]byte(value))
	return fmt.Sprintf("%x", digest.Sum(nil))[:32]
}

func verifiedClaims(claims jwt.MapClaims) (VerifiedClaims, error) {
	userID, okUser := claims["sub"].(string)
	sessionID, okSession := claims["sid"].(string)
	familyID, okFamily := claims["fid"].(string)
	jti, okJTI := claims["jti"].(string)
	clientType, okClient := claims["client_type"].(string)
	issuedAt, err := claims.GetIssuedAt()
	if !okUser || !okSession || !okFamily || !okJTI || !okClient || err != nil || issuedAt == nil {
		return VerifiedClaims{}, ErrTokenInvalid
	}
	assurance := make([]string, 0)
	if values, ok := claims["amr"].([]any); ok {
		for _, value := range values {
			if text, ok := value.(string); ok {
				assurance = append(assurance, text)
			}
		}
	}
	workspaceID, _ := claims["wid"].(string)
	workspaceType, _ := claims["wtype"].(string)
	roles := make([]string, 0)
	if values, ok := claims["roles"].([]any); ok {
		for _, value := range values {
			if text, ok := value.(string); ok {
				roles = append(roles, text)
			}
		}
	}
	if (workspaceID == "") != (workspaceType == "") {
		return VerifiedClaims{}, ErrTokenInvalid
	}
	if strings.TrimSpace(userID) == "" || strings.TrimSpace(sessionID) == "" {
		return VerifiedClaims{}, ErrTokenInvalid
	}
	return VerifiedClaims{
		UserID: userID, SessionID: sessionID, FamilyID: familyID, JTI: jti,
		ClientType: clientType, Assurance: assurance, WorkspaceID: workspaceID,
		WorkspaceType: workspaceType, Roles: roles, IssuedAt: issuedAt.Time,
	}, nil
}
