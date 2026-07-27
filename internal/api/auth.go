package api

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/sorotrail/sorotrail/internal/store"
)

type authCtxKey string

const apiKeyIDCtxKey authCtxKey = "api_key_id"

// AuthHandler wraps the API key authentication logic.
type AuthHandler struct {
	keyStore    *store.APIKeyStore
	authEnabled bool
}

// NewAuthHandler creates an AuthHandler. When authEnabled is false, the
// middleware is a no-op pass-through (all requests succeed).
func NewAuthHandler(keyStore *store.APIKeyStore, authEnabled bool) *AuthHandler {
	return &AuthHandler{keyStore: keyStore, authEnabled: authEnabled}
}

// Middleware returns an HTTP middleware that authenticates requests.
// When authEnabled is true, all requests except those to /health must
// carry a valid Authorization: Bearer <key> header. When authEnabled is
// false, the middleware is a pass-through.
//
// The authenticated API key ID is stored in the request context so
// downstream handlers can use it (e.g. to update last_used_at).
func (h *AuthHandler) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !h.authEnabled {
			next.ServeHTTP(w, r)
			return
		}

		// /health is always open even when auth is enabled.
		if r.URL.Path == "/health" {
			next.ServeHTTP(w, r)
			return
		}

		auth := r.Header.Get("Authorization")
		if auth == "" {
			writeError(w, http.StatusUnauthorized, errors.New("missing Authorization header"))
			return
		}

		// Parse "Bearer <key>".
		const prefix = "Bearer "
		if len(auth) < len(prefix) || subtle.ConstantTimeCompare([]byte(auth[:len(prefix)]), []byte(prefix)) != 1 {
			writeError(w, http.StatusUnauthorized, errors.New("invalid Authorization format (expected Bearer <key>)"))
			return
		}
		key := auth[len(prefix):]

		apiKey, err := h.keyStore.AuthenticateAPIKey(r.Context(), key)
		if err != nil {
			if errors.Is(err, store.ErrNotFound) {
				writeError(w, http.StatusUnauthorized, errors.New("invalid or revoked API key"))
				return
			}
			loggerFromContext(r.Context()).Error("authenticating API key", "error", err)
			writeError(w, http.StatusInternalServerError, errors.New("authentication failed"))
			return
		}

		// Store the key ID in the context for downstream use.
		ctx := context.WithValue(r.Context(), apiKeyIDCtxKey, apiKey.ID)

		// Update last_used_at asynchronously (best-effort) so the fast
		// path of request handling is never blocked by a metadata write.
		go h.keyStore.TouchAPIKey(context.Background(), apiKey.ID)

		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// AdminAPIHandler provides admin endpoints for API key management.
type AdminAPIHandler struct {
	keyStore *store.APIKeyStore
	log      adminLogger
}

type adminLogger interface {
	Info(msg string, args ...any)
	Error(msg string, args ...any)
}

// NewAdminAPIHandler creates an AdminAPIHandler.
func NewAdminAPIHandler(keyStore *store.APIKeyStore, log adminLogger) *AdminAPIHandler {
	return &AdminAPIHandler{keyStore: keyStore, log: log}
}

type createKeyRequest struct {
	Name string `json:"name"`
}

type createKeyResponse struct {
	ID        int64     `json:"id"`
	Name      string    `json:"name"`
	Key       string    `json:"key"` // plaintext, shown once
	Prefix    string    `json:"prefix"`
	CreatedAt time.Time `json:"created_at"`
}

// HandleCreateKey creates a new API key. The plaintext key is returned
// once in the response and is never stored or logged.
func (h *AdminAPIHandler) HandleCreateKey(w http.ResponseWriter, r *http.Request) {
	var req createKeyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, fmt.Errorf("invalid request body: %w", err))
		return
	}
	if req.Name == "" {
		req.Name = "unnamed"
	}

	plaintext, hash, prefix, err := store.GenerateAPIKey()
	if err != nil {
		h.log.Error("generating API key", "error", err)
		writeError(w, http.StatusInternalServerError, errors.New("generating API key failed"))
		return
	}

	apiKey, err := h.keyStore.CreateAPIKey(r.Context(), req.Name, hash, prefix)
	if err != nil {
		h.log.Error("persisting API key", "error", err)
		writeError(w, http.StatusInternalServerError, errors.New("creating API key failed"))
		return
	}

	writeJSON(w, http.StatusCreated, createKeyResponse{
		ID:        apiKey.ID,
		Name:      apiKey.Name,
		Key:       plaintext,
		Prefix:    apiKey.Prefix,
		CreatedAt: apiKey.CreatedAt,
	})
}

type listKeysResponse struct {
	Keys  []store.APIKey `json:"keys"`
	Count int            `json:"count"`
}

// HandleListKeys returns all API keys (without hashes).
func (h *AdminAPIHandler) HandleListKeys(w http.ResponseWriter, r *http.Request) {
	keys, err := h.keyStore.ListAPIKeys(r.Context())
	if err != nil {
		h.log.Error("listing API keys", "error", err)
		writeError(w, http.StatusInternalServerError, errors.New("listing API keys failed"))
		return
	}
	if keys == nil {
		keys = []store.APIKey{}
	}
	writeJSON(w, http.StatusOK, listKeysResponse{Keys: keys, Count: len(keys)})
}

// HandleRevokeKey revokes an API key by ID.
func (h *AdminAPIHandler) HandleRevokeKey(w http.ResponseWriter, r *http.Request) {
	idStr := chi.URLParam(r, "id")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil || id <= 0 {
		writeError(w, http.StatusBadRequest, fmt.Errorf("invalid key id %q", idStr))
		return
	}

	if err := h.keyStore.RevokeAPIKey(r.Context(), id); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, http.StatusNotFound, fmt.Errorf("API key %d not found or already revoked", id))
			return
		}
		h.log.Error("revoking API key", "id", id, "error", err)
		writeError(w, http.StatusInternalServerError, errors.New("revoking API key failed"))
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"revoked": true,
		"key_id":  id,
	})
}
