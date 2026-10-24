// Package store persists analyses in SQLite as JSON snapshots with indexed
// summary columns. Only already-masked data is ever written.
package store

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"

	_ "modernc.org/sqlite" // pure-Go SQLite driver

	"github.com/TroubieD3v/cloudgraph/internal/model"
)

// Store is a SQLite-backed analysis history.
type Store struct{ db *sql.DB }

// Item is the list view of a stored analysis.
type Item struct {
	ID        string        `json:"id"`
	Name      string        `json:"name"`
	CreatedAt string        `json:"createdAt"`
	Summary   model.Summary `json:"summary"`
}

// ErrNotFound is returned when an analysis does not exist.
var ErrNotFound = errors.New("analysis not found")

// Open opens (and migrates) a database file; ":memory:" gives a private in-memory DB.
func Open(path string) (*Store, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	if path == ":memory:" {
		db.SetMaxOpenConns(1)
	}
	const schema = `
CREATE TABLE IF NOT EXISTS analyses (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  created_at TEXT NOT NULL,
  resources INTEGER NOT NULL,
  findings INTEGER NOT NULL,
  paths INTEGER NOT NULL,
  summary TEXT NOT NULL,
  snapshot BLOB NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_analyses_created ON analyses(created_at DESC);`
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("migrate: %w", err)
	}
	return &Store{db: db}, nil
}

// Close releases the database.
func (s *Store) Close() error { return s.db.Close() }

// Save stores an analysis snapshot.
func (s *Store) Save(a *model.Analysis) error {
	b, err := json.Marshal(a)
	if err != nil {
		return err
	}
	sum, err := json.Marshal(a.Summary)
	if err != nil {
		return err
	}
	_, err = s.db.Exec(`INSERT OR REPLACE INTO analyses(id,name,created_at,resources,findings,paths,summary,snapshot) VALUES(?,?,?,?,?,?,?,?)`,
		a.ID, a.Name, a.CreatedAt, a.Summary.Resources, a.Summary.Findings, a.Summary.Paths, string(sum), b)
	return err
}

// Get loads a snapshot.
func (s *Store) Get(id string) (*model.Analysis, error) {
	var b []byte
	err := s.db.QueryRow(`SELECT snapshot FROM analyses WHERE id=?`, id).Scan(&b)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	var a model.Analysis
	if err := json.Unmarshal(b, &a); err != nil {
		return nil, err
	}
	return &a, nil
}

// List returns the history, newest first.
func (s *Store) List() ([]Item, error) {
	rows, err := s.db.Query(`SELECT id,name,created_at,summary FROM analyses ORDER BY created_at DESC, id LIMIT 200`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []Item{}
	for rows.Next() {
		var it Item
		var sum string
		if err := rows.Scan(&it.ID, &it.Name, &it.CreatedAt, &sum); err != nil {
			return nil, err
		}
		if err := json.Unmarshal([]byte(sum), &it.Summary); err != nil {
			return nil, err
		}
		items = append(items, it)
	}
	return items, rows.Err()
}

// Delete removes a snapshot.
func (s *Store) Delete(id string) error {
	res, err := s.db.Exec(`DELETE FROM analyses WHERE id=?`, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}
