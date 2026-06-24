package config

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/chain305/chainsaw-core/pgstore"
	"github.com/chain305/chainsaw-core/tenancy"
)

// TrafficView represents a saved dashboard filter preset.
type TrafficView struct {
	ID         string    `json:"id"`
	OrgID      string    `json:"org_id,omitempty"`
	Name       string    `json:"name"`
	SearchTerm string    `json:"searchTerm,omitempty"`
	Repository string    `json:"repository,omitempty"`
	Start      string    `json:"start,omitempty"`
	End        string    `json:"end,omitempty"`
	CreatedAt  time.Time `json:"createdAt"`
}

// ListTrafficViews returns saved traffic views ordered by most recent.
func ListTrafficViews(store *pgstore.Store, orgID string) ([]TrafficView, error) {
	if store == nil {
		return nil, errors.New("database store is required")
	}
	orgID = tenancy.NormalizeOrgID(orgID)
	rows, err := store.DB().Query(`SELECT id, org_id, name, search_term, repository, start, "end", created_at
		FROM traffic_views WHERE org_id=? ORDER BY created_at DESC, name ASC`, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var views []TrafficView
	for rows.Next() {
		var view TrafficView
		if err := rows.Scan(&view.ID, &view.OrgID, &view.Name, &view.SearchTerm, &view.Repository, &view.Start, &view.End, &view.CreatedAt); err != nil {
			return nil, err
		}
		views = append(views, view)
	}
	return views, rows.Err()
}

// SaveTrafficView inserts a new traffic view and returns the updated collection.
func SaveTrafficView(store *pgstore.Store, view TrafficView) ([]TrafficView, error) {
	if store == nil {
		return nil, errors.New("database store is required")
	}
	orgID := tenancy.NormalizeOrgID(view.OrgID)
	view.Name = strings.TrimSpace(view.Name)
	if view.Name == "" {
		return nil, errors.New("name is required")
	}
	view.SearchTerm = strings.TrimSpace(view.SearchTerm)
	view.Repository = strings.TrimSpace(view.Repository)
	view.Start = strings.TrimSpace(view.Start)
	view.End = strings.TrimSpace(view.End)
	if view.ID == "" {
		id, err := generateTrafficViewID()
		if err != nil {
			return nil, err
		}
		view.ID = id
	}
	createdAt := view.CreatedAt
	if createdAt.IsZero() {
		createdAt = time.Now().UTC()
	}
	_, err := store.DB().Exec(`INSERT INTO traffic_views(id, org_id, name, search_term, repository, start, "end", created_at)
		VALUES(?,?,?,?,?,?,?,?)`,
		view.ID, orgID, view.Name, nullWhenEmpty(view.SearchTerm), nullWhenEmpty(view.Repository),
		nullWhenEmpty(view.Start), nullWhenEmpty(view.End), createdAt)
	if err != nil {
		return nil, err
	}
	return ListTrafficViews(store, orgID)
}

// DeleteTrafficView removes a saved view and returns the updated collection.
func DeleteTrafficView(store *pgstore.Store, orgID, id string) ([]TrafficView, error) {
	if store == nil {
		return nil, errors.New("database store is required")
	}
	orgID = tenancy.NormalizeOrgID(orgID)
	id = strings.TrimSpace(id)
	if id == "" {
		return nil, errors.New("view id is required")
	}
	if _, err := store.DB().Exec(`DELETE FROM traffic_views WHERE org_id=? AND id=?`, orgID, id); err != nil {
		return nil, err
	}
	return ListTrafficViews(store, orgID)
}

func generateTrafficViewID() (string, error) {
	var buf [12]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return "", fmt.Errorf("generate traffic view id: %w", err)
	}
	return strings.TrimRight(base64.RawURLEncoding.EncodeToString(buf[:]), "="), nil
}

func nullWhenEmpty(value string) any {
	if strings.TrimSpace(value) == "" {
		return nil
	}
	return value
}
