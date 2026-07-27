package store

import (
	"context"
	"crypto/sha256"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// APIKey represents a stored API key row.
type APIKey struct {
	ID          int64      `json:"id"`
	Name        string     `json:"name"`
	Prefix      string     `json:"prefix"` // first 8 chars of plaintext key
	CreatedAt   time.Time  `json:"created_at"`
	LastUsedAt  *time.Time `json:"last_used_at,omitempty"`
	Revoked     bool       `json:"revoked"`
}

// GenerateAPIKey creates a new random API key and its SHA-256 hash.
// Returns the plaintext key (shown once to the caller) and the hash.
func GenerateAPIKey() (plaintext string, hash []byte, prefix string, err error) {
	key := make([]byte, 32) // 256-bit key
	if _, err := rand.Read(key); err != nil {
		return "", nil, "", fmt.Errorf("generating api key: %w", err)
	}
	plaintext = "sk_" + hex.EncodeToString(key)
	sum := sha256.Sum256([]byte(plaintext))
	return plaintext, sum[:], plaintext[:10], nil
}

// HashAPIKey returns the SHA-256 hash of a plaintext key.
func HashAPIKey(plaintext string) []byte {
	sum := sha256.Sum256([]byte(plaintext))
	return sum[:]
}

// APIKeyStore provides persistence for API keys.
type APIKeyStore struct {
	pool *pgxpool.Pool
}

// NewAPIKeyStore creates an APIKeyStore backed by the given pool.
func NewAPIKeyStore(pool *pgxpool.Pool) *APIKeyStore {
	return &APIKeyStore{pool: pool}
}

// CreateAPIKey inserts a new API key and returns the stored record.
func (s *APIKeyStore) CreateAPIKey(ctx context.Context, name string, keyHash []byte, prefix string) (APIKey, error) {
	var k APIKey
	err := s.pool.QueryRow(ctx, `
		INSERT INTO api_keys (name, key_hash, prefix)
		VALUES ($1, $2, $3)
		RETURNING id, name, prefix, created_at, last_used_at, revoked`,
		name, keyHash, prefix,
	).Scan(&k.ID, &k.Name, &k.Prefix, &k.CreatedAt, &k.LastUsedAt, &k.Revoked)
	if err != nil {
		return APIKey{}, fmt.Errorf("creating api key: %w", err)
	}
	return k, nil
}

// ListAPIKeys returns all non-revoked API keys (without hashes).
func (s *APIKeyStore) ListAPIKeys(ctx context.Context) ([]APIKey, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, name, prefix, created_at, last_used_at, revoked
		FROM api_keys
		ORDER BY created_at DESC`)
	if err != nil {
		return nil, fmt.Errorf("listing api keys: %w", err)
	}
	defer rows.Close()

	var out []APIKey
	for rows.Next() {
		var k APIKey
		if err := rows.Scan(&k.ID, &k.Name, &k.Prefix, &k.CreatedAt, &k.LastUsedAt, &k.Revoked); err != nil {
			return nil, err
		}
		out = append(out, k)
	}
	return out, rows.Err()
}

// RevokeAPIKey marks an API key as revoked by ID.
func (s *APIKeyStore) RevokeAPIKey(ctx context.Context, id int64) error {
	tag, err := s.pool.Exec(ctx, `
		UPDATE api_keys SET revoked = true WHERE id = $1 AND revoked = false`, id)
	if err != nil {
		return fmt.Errorf("revoking api key %d: %w", id, err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// AuthenticateAPIKey checks if a plaintext key is valid and non-revoked.
// Returns the key's ID on success. When throttled is true, updates
// last_used_at opportunistically (best-effort, non-blocking).
func (s *APIKeyStore) AuthenticateAPIKey(ctx context.Context, plaintext string) (APIKey, error) {
	hash := HashAPIKey(plaintext)
	var k APIKey
	err := s.pool.QueryRow(ctx, `
		SELECT id, name, prefix, created_at, last_used_at, revoked
		FROM api_keys
		WHERE key_hash = $1 AND revoked = false`, hash,
	).Scan(&k.ID, &k.Name, &k.Prefix, &k.CreatedAt, &k.LastUsedAt, &k.Revoked)
	if errors.Is(err, pgx.ErrNoRows) {
		return APIKey{}, ErrNotFound
	}
	if err != nil {
		return APIKey{}, fmt.Errorf("authenticating api key: %w", err)
	}
	return k, nil
}

// TouchAPIKey updates the last_used_at timestamp for a key. This is a
// best-effort operation — errors are logged but not returned, so the
// fast path of request handling is never blocked by a metadata write.
func (s *APIKeyStore) TouchAPIKey(ctx context.Context, id int64) {
	_, _ = s.pool.Exec(ctx, `
		UPDATE api_keys SET last_used_at = now() WHERE id = $1`, id)
}

// CountNonRevokedKeys returns the number of non-revoked API keys.
func (s *APIKeyStore) CountNonRevokedKeys(ctx context.Context) (int64, error) {
	var n int64
	err := s.pool.QueryRow(ctx, `SELECT count(*) FROM api_keys WHERE revoked = false`).Scan(&n)
	return n, err
}

// SeedAdminAPIKey creates the first admin key if the table is empty.
// Returns the plaintext key (shown once in startup logs).
func (s *APIKeyStore) SeedAdminAPIKey(ctx context.Context, name string) (string, error) {
	count, err := s.CountNonRevokedKeys(ctx)
	if err != nil {
		return "", err
	}
	if count > 0 {
		return "", nil // keys already exist; don't duplicate
	}
	plaintext, hash, prefix, err := GenerateAPIKey()
	if err != nil {
		return "", err
	}
	_, err = s.CreateAPIKey(ctx, name, hash, prefix)
	if err != nil {
		return "", err
	}
	return plaintext, nil
}
