package config

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/chain305/chainsaw-core/pgstore"
)

var (
	// ErrClientCredentialExists indicates the client_id already exists.
	ErrClientCredentialExists = errors.New("client credential already exists")
	// ErrClientCredentialNotFound indicates the requested client_id is missing.
	ErrClientCredentialNotFound = errors.New("client credential not found")
	// ErrInvalidClientCredential indicates the provided payload is invalid.
	ErrInvalidClientCredential = errors.New("invalid client credential")
)

var clientIDPattern = regexp.MustCompile(`^[a-z][a-z0-9-_]{2,31}$`)

// ValidClientTypes defines the allowed client_type values.
var ValidClientTypes = map[string]bool{
	"end-user":      true,
	"service-token": true,
	"ai-agent":      true,
}

// ClientCredential represents metadata about a repository client credential.
type ClientCredential struct {
	OrgID                  string     `json:"org_id"`
	ID                     string     `json:"client_id"`
	Name                   string     `json:"name,omitempty"`
	ClientType             string     `json:"client_type"`
	CreatedBy              string     `json:"created_by_user_id,omitempty"`
	Enabled                bool       `json:"enabled"`
	Expiry                 *time.Time `json:"expiry,omitempty"`
	AuthorizedRepositories []string   `json:"authorized_repositories,omitempty"`
	CreatedAt              time.Time  `json:"created_at"`
	DisabledAt             *time.Time `json:"disabled_at,omitempty"`
}

// ClientCredentialSecret exposes secret hashes for runtime validation.
type ClientCredentialSecret struct {
	ClientCredential
	SecretHash string
}

// ListClientCredentials returns configured client credentials for an org.
// When orgID is empty, all credentials are returned.
func ListClientCredentials(store *pgstore.Store, orgID string) ([]ClientCredential, error) {
	if store == nil {
		return nil, errors.New("database store is required")
	}
	orgID = strings.TrimSpace(orgID)
	query := `SELECT org_id, client_id, name, client_type, created_by_user_id, enabled, expiry_date, authorized_repositories, created_at, disabled_at
		FROM client_credentials`
	args := []any{}
	if orgID != "" {
		query += ` WHERE org_id=?`
		args = append(args, orgID)
	}
	query += ` ORDER BY client_id`
	rows, err := store.DB().Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var creds []ClientCredential
	for rows.Next() {
		record, _, err := scanClientCredential(rows, false)
		if err != nil {
			return nil, err
		}
		creds = append(creds, record)
	}
	return creds, rows.Err()
}

// ListClientCredentialSecrets returns client credentials including hashed secrets.
// When orgID is empty, all credentials are returned.
func ListClientCredentialSecrets(store *pgstore.Store, orgID string) ([]ClientCredentialSecret, error) {
	if store == nil {
		return nil, errors.New("database store is required")
	}
	orgID = strings.TrimSpace(orgID)
	query := `SELECT org_id, client_id, name, client_type, created_by_user_id, secret_hash, enabled, expiry_date, authorized_repositories, created_at, disabled_at
		FROM client_credentials`
	args := []any{}
	if orgID != "" {
		query += ` WHERE org_id=?`
		args = append(args, orgID)
	}
	// ORDER BY client_id, org_id: stable tiebreaker for the (rare) case
	// where two orgs minted the same client_id. Pre-fix this iteration
	// order was undefined and the in-memory cache silently reattributed
	// one org's row to the other's slot (production incident 2026-05-19).
	// The cache is now composite-keyed (see clientRegistry) so the
	// tiebreaker is no longer load-bearing for correctness — but
	// deterministic load order keeps legacy first-match-by-clientID
	// lookups stable across restarts.
	query += ` ORDER BY client_id, org_id`
	rows, err := store.DB().Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var records []ClientCredentialSecret
	for rows.Next() {
		meta, hash, err := scanClientCredential(rows, true)
		if err != nil {
			return nil, err
		}
		records = append(records, ClientCredentialSecret{
			ClientCredential: meta,
			SecretHash:       hash,
		})
	}
	return records, rows.Err()
}

// CreateClientCredential inserts a new credential and returns the generated secret.
func CreateClientCredential(store *pgstore.Store, orgID, createdBy, id, name, clientType string, expiry *time.Time, authorizedRepos []string) (ClientCredential, string, error) {
	if store == nil {
		return ClientCredential{}, "", errors.New("database store is required")
	}
	orgID = strings.TrimSpace(orgID)
	if orgID == "" {
		return ClientCredential{}, "", fmt.Errorf("%w: org_id is required", ErrInvalidClientCredential)
	}
	clientID := normalizeClientID(id)
	if err := validateClientID(clientID); err != nil {
		return ClientCredential{}, "", err
	}
	clientType = strings.TrimSpace(clientType)
	if clientType == "" {
		clientType = "end-user"
	}
	if !ValidClientTypes[clientType] {
		return ClientCredential{}, "", fmt.Errorf("%w: invalid client_type %q, must be one of: end-user, service-token, ai-agent", ErrInvalidClientCredential, clientType)
	}
	repos, err := normalizeAuthorizedRepositories(authorizedRepos)
	if err != nil {
		return ClientCredential{}, "", err
	}
	reposJSON, err := marshalAuthorizedRepositories(repos)
	if err != nil {
		return ClientCredential{}, "", err
	}
	secret, err := generateRandomPassword()
	if err != nil {
		return ClientCredential{}, "", err
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(secret), bcrypt.DefaultCost)
	if err != nil {
		return ClientCredential{}, "", fmt.Errorf("hash client secret: %w", err)
	}
	err = store.WithTx(context.Background(), func(tx *sql.Tx) error {
		var exists bool
		if err := tx.QueryRow(`SELECT EXISTS(SELECT 1 FROM client_credentials WHERE org_id=? AND client_id=?)`, orgID, clientID).
			Scan(&exists); err != nil {
			return err
		}
		if exists {
			return fmt.Errorf("%w: %s", ErrClientCredentialExists, clientID)
		}
		_, err := tx.Exec(`INSERT INTO client_credentials(org_id, client_id, secret_hash, enabled, name, created_by_user_id, client_type, expiry_date, authorized_repositories)
			VALUES(?,?,?,?,?,?,?,?,?)`, orgID, clientID, string(hash), 1, strings.TrimSpace(name), strings.TrimSpace(createdBy), clientType, nullableTime(expiry), reposJSON)
		return err
	})
	if err != nil {
		return ClientCredential{}, "", err
	}
	meta, err := fetchClientCredential(store.DB(), orgID, clientID)
	if err != nil {
		return ClientCredential{}, "", err
	}
	return meta, secret, nil
}

// SetClientCredentialEnabled toggles the enabled flag for a credential.
func SetClientCredentialEnabled(store *pgstore.Store, orgID, id string, enabled bool) (ClientCredential, error) {
	if store == nil {
		return ClientCredential{}, errors.New("database store is required")
	}
	orgID = strings.TrimSpace(orgID)
	if orgID == "" {
		return ClientCredential{}, fmt.Errorf("%w: org_id is required", ErrInvalidClientCredential)
	}
	clientID := normalizeClientID(id)
	if clientID == "" {
		return ClientCredential{}, fmt.Errorf("%w: client_id is required", ErrInvalidClientCredential)
	}
	err := store.WithTx(context.Background(), func(tx *sql.Tx) error {
		var disabledAt any
		if enabled {
			disabledAt = nil
		} else {
			disabledAt = time.Now().UTC()
		}
		res, err := tx.Exec(`UPDATE client_credentials SET enabled=?, disabled_at=? WHERE org_id=? AND client_id=?`,
			boolInt(enabled), disabledAt, orgID, clientID)
		if err != nil {
			return err
		}
		rows, err := res.RowsAffected()
		if err != nil {
			return err
		}
		if rows == 0 {
			return fmt.Errorf("%w: %s", ErrClientCredentialNotFound, clientID)
		}
		return nil
	})
	if err != nil {
		return ClientCredential{}, err
	}
	return fetchClientCredential(store.DB(), orgID, clientID)
}

// UpdateClientType changes the client_type for a credential.
func UpdateClientType(store *pgstore.Store, orgID, id, clientType string) (ClientCredential, error) {
	if store == nil {
		return ClientCredential{}, errors.New("database store is required")
	}
	orgID = strings.TrimSpace(orgID)
	if orgID == "" {
		return ClientCredential{}, fmt.Errorf("%w: org_id is required", ErrInvalidClientCredential)
	}
	clientID := normalizeClientID(id)
	if clientID == "" {
		return ClientCredential{}, fmt.Errorf("%w: client_id is required", ErrInvalidClientCredential)
	}
	clientType = strings.TrimSpace(clientType)
	if !ValidClientTypes[clientType] {
		return ClientCredential{}, fmt.Errorf("%w: invalid client_type %q", ErrInvalidClientCredential, clientType)
	}
	res, err := store.DB().Exec(`UPDATE client_credentials SET client_type=?, updated_at=? WHERE org_id=? AND client_id=?`,
		clientType, time.Now().UTC(), orgID, clientID)
	if err != nil {
		return ClientCredential{}, err
	}
	rows, err := res.RowsAffected()
	if err != nil {
		return ClientCredential{}, err
	}
	if rows == 0 {
		return ClientCredential{}, fmt.Errorf("%w: %s", ErrClientCredentialNotFound, clientID)
	}
	return fetchClientCredential(store.DB(), orgID, clientID)
}

// UpdateClientCredentialAccess changes expiry and repository scope fields.
func UpdateClientCredentialAccess(store *pgstore.Store, orgID, id string, expiry *time.Time, expirySet bool, authorizedRepos []string, reposSet bool) (ClientCredential, error) {
	if store == nil {
		return ClientCredential{}, errors.New("database store is required")
	}
	orgID = strings.TrimSpace(orgID)
	if orgID == "" {
		return ClientCredential{}, fmt.Errorf("%w: org_id is required", ErrInvalidClientCredential)
	}
	clientID := normalizeClientID(id)
	if clientID == "" {
		return ClientCredential{}, fmt.Errorf("%w: client_id is required", ErrInvalidClientCredential)
	}
	sets := []string{}
	args := []any{}
	if expirySet {
		sets = append(sets, "expiry_date=?")
		args = append(args, nullableTime(expiry))
	}
	if reposSet {
		repos, err := normalizeAuthorizedRepositories(authorizedRepos)
		if err != nil {
			return ClientCredential{}, err
		}
		reposJSON, err := marshalAuthorizedRepositories(repos)
		if err != nil {
			return ClientCredential{}, err
		}
		sets = append(sets, "authorized_repositories=?")
		args = append(args, reposJSON)
	}
	if len(sets) == 0 {
		return fetchClientCredential(store.DB(), orgID, clientID)
	}
	sets = append(sets, "updated_at=?")
	args = append(args, time.Now().UTC(), orgID, clientID)
	res, err := store.DB().Exec(`UPDATE client_credentials SET `+strings.Join(sets, ", ")+` WHERE org_id=? AND client_id=?`, args...)
	if err != nil {
		return ClientCredential{}, err
	}
	rows, err := res.RowsAffected()
	if err != nil {
		return ClientCredential{}, err
	}
	if rows == 0 {
		return ClientCredential{}, fmt.Errorf("%w: %s", ErrClientCredentialNotFound, clientID)
	}
	return fetchClientCredential(store.DB(), orgID, clientID)
}

// DeleteClientCredential removes a credential permanently.
func DeleteClientCredential(store *pgstore.Store, orgID, id string) error {
	if store == nil {
		return errors.New("database store is required")
	}
	orgID = strings.TrimSpace(orgID)
	if orgID == "" {
		return fmt.Errorf("%w: org_id is required", ErrInvalidClientCredential)
	}
	clientID := normalizeClientID(id)
	if clientID == "" {
		return fmt.Errorf("%w: client_id is required", ErrInvalidClientCredential)
	}
	res, err := store.DB().Exec(`DELETE FROM client_credentials WHERE org_id=? AND client_id=?`, orgID, clientID)
	if err != nil {
		return err
	}
	rows, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if rows == 0 {
		return fmt.Errorf("%w: %s", ErrClientCredentialNotFound, clientID)
	}
	return nil
}

func fetchClientCredential(db *sql.DB, orgID, id string) (ClientCredential, error) {
	row := db.QueryRow(`SELECT org_id, client_id, name, client_type, created_by_user_id, enabled, expiry_date, authorized_repositories, created_at, disabled_at
		FROM client_credentials WHERE org_id=? AND client_id=?`, orgID, id)
	meta, _, err := scanClientCredential(row, false)
	return meta, err
}

type credentialScanner interface {
	Scan(dest ...any) error
}

func scanClientCredential(row credentialScanner, includeHash bool) (ClientCredential, string, error) {
	var (
		orgID      string
		clientID   string
		name       sql.NullString
		clientType sql.NullString
		createdBy  sql.NullString
		hash       string
		enabled    int
		expiry     sql.NullTime
		reposRaw   sql.NullString
		createdAt  time.Time
		disabled   sql.NullTime
	)
	dest := []any{&orgID, &clientID, &name, &clientType, &createdBy}
	if includeHash {
		dest = append(dest, &hash)
	}
	dest = append(dest, &enabled, &expiry, &reposRaw, &createdAt, &disabled)
	if err := row.Scan(dest...); err != nil {
		return ClientCredential{}, "", err
	}
	repos, err := parseAuthorizedRepositories(reposRaw.String)
	if err != nil {
		return ClientCredential{}, "", err
	}
	ct := strings.TrimSpace(clientType.String)
	if ct == "" {
		ct = "end-user"
	}
	cred := ClientCredential{
		OrgID:                  orgID,
		ID:                     clientID,
		Name:                   strings.TrimSpace(name.String),
		ClientType:             ct,
		CreatedBy:              strings.TrimSpace(createdBy.String),
		Enabled:                enabled != 0,
		AuthorizedRepositories: repos,
		CreatedAt:              createdAt,
	}
	if expiry.Valid {
		ts := expiry.Time
		cred.Expiry = &ts
	}
	if disabled.Valid {
		ts := disabled.Time
		cred.DisabledAt = &ts
	}
	return cred, hash, nil
}

func normalizeAuthorizedRepositories(repos []string) ([]string, error) {
	if len(repos) == 0 {
		return nil, nil
	}
	out := make([]string, 0, len(repos))
	seen := map[string]struct{}{}
	for _, repo := range repos {
		repo = strings.TrimSpace(repo)
		if repo == "" {
			continue
		}
		if strings.EqualFold(repo, "all") || repo == "*" {
			return nil, nil
		}
		key := strings.ToLower(repo)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, repo)
	}
	if len(out) == 0 {
		return nil, nil
	}
	return out, nil
}

func marshalAuthorizedRepositories(repos []string) (any, error) {
	if len(repos) == 0 {
		return nil, nil
	}
	data, err := json.Marshal(repos)
	if err != nil {
		return nil, fmt.Errorf("%w: authorized_repositories", ErrInvalidClientCredential)
	}
	return string(data), nil
}

func parseAuthorizedRepositories(raw string) ([]string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, nil
	}
	var repos []string
	if err := json.Unmarshal([]byte(raw), &repos); err != nil {
		return nil, fmt.Errorf("%w: authorized_repositories", ErrInvalidClientCredential)
	}
	return normalizeAuthorizedRepositories(repos)
}

func nullableTime(ts *time.Time) any {
	if ts == nil {
		return nil
	}
	return ts.UTC()
}

func normalizeClientID(id string) string {
	return strings.ToLower(strings.TrimSpace(id))
}

func validateClientID(id string) error {
	if id == "" {
		return fmt.Errorf("%w: client_id is required", ErrInvalidClientCredential)
	}
	if !clientIDPattern.MatchString(id) {
		return fmt.Errorf("%w: client_id must be 3-32 characters: lowercase letters, numbers, dash or underscore", ErrInvalidClientCredential)
	}
	return nil
}
