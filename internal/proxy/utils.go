package proxy

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Session represents a captured user session
type Session struct {
	ID         string    `json:"id"`
	Cookies    string    `json:"cookies"`
	UserAgent  string    `json:"user_agent"`
	IP         string    `json:"ip"`
	LastActive time.Time `json:"last_active"`
	Metadata   string    `json:"metadata"`
}

// SessionManager handles all session operations
type SessionManager struct {
	db     *sql.DB
	mu     sync.RWMutex
	logger *log.Logger
}

// NewSessionManager creates a new session manager instance
func NewSessionManager(db *sql.DB, logger *log.Logger) *SessionManager {
	if logger == nil {
		logger = log.Default()
	}
	return &SessionManager{
		db:     db,
		logger: logger,
	}
}

// Save stores a session in the database
func (sm *SessionManager) Save(ctx context.Context, session Session) error {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	if sm.db == nil {
		return errors.New("database not initialized")
	}

	_, err := sm.db.ExecContext(ctx, `
		INSERT OR REPLACE INTO sessions 
		(id, cookies, user_agent, ip, last_active, metadata) 
		VALUES (?, ?, ?, ?, ?, ?)`,
		session.ID,
		session.Cookies,
		session.UserAgent,
		session.IP,
		session.LastActive.Format(time.RFC3339),
		session.Metadata,
	)

	if err != nil {
		sm.logger.Printf("Failed to save session %s: %v", session.ID, err)
		return fmt.Errorf("failed to save session: %w", err)
	}
	return nil
}

// GetByID retrieves a session by its ID
func (sm *SessionManager) GetByID(ctx context.Context, id string) (Session, error) {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	var s Session
	var lastActive string

	err := sm.db.QueryRowContext(ctx, `
		SELECT id, cookies, user_agent, ip, last_active, metadata 
		FROM sessions WHERE id = ?`, id).Scan(
		&s.ID,
		&s.Cookies,
		&s.UserAgent,
		&s.IP,
		&lastActive,
		&s.Metadata,
	)

	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return Session{}, fmt.Errorf("session not found")
		}
		return Session{}, fmt.Errorf("failed to get session: %w", err)
	}

	s.LastActive, _ = time.Parse(time.RFC3339, lastActive)
	return s, nil
}

// GetAll retrieves all sessions sorted by last activity
func (sm *SessionManager) GetAll(ctx context.Context) ([]Session, error) {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	rows, err := sm.db.QueryContext(ctx, `
		SELECT id, cookies, user_agent, ip, last_active, metadata 
		FROM sessions ORDER BY last_active DESC`)
	if err != nil {
		return nil, fmt.Errorf("failed to query sessions: %w", err)
	}
	defer rows.Close()

	var sessions []Session
	for rows.Next() {
		var s Session
		var lastActive string
		if err := rows.Scan(
			&s.ID,
			&s.Cookies,
			&s.UserAgent,
			&s.IP,
			&lastActive,
			&s.Metadata,
		); err != nil {
			return nil, fmt.Errorf("failed to scan session: %w", err)
		}

		s.LastActive, _ = time.Parse(time.RFC3339, lastActive)
		sessions = append(sessions, s)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("rows error: %w", err)
	}

	return sessions, nil
}

// CleanOld removes sessions older than the specified duration
func (sm *SessionManager) CleanOld(ctx context.Context, maxAge time.Duration) (int64, error) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	res, err := sm.db.ExecContext(ctx, `
		DELETE FROM sessions 
		WHERE last_active < ?`,
		time.Now().Add(-maxAge).Format(time.RFC3339),
	)

	if err != nil {
		sm.logger.Printf("Failed to clean old sessions: %v", err)
		return 0, fmt.Errorf("failed to clean old sessions: %w", err)
	}

	count, _ := res.RowsAffected()
	return count, nil
}

// GetClientIP extracts the client IP from a request, considering proxies
func GetClientIP(r *http.Request) string {
	forwarded := r.Header.Get("X-Forwarded-For")
	if forwarded != "" {
		return strings.Split(forwarded, ",")[0]
	}
	if realIP := r.Header.Get("X-Real-IP"); realIP != "" {
		return realIP
	}
	ip, _, _ := net.SplitHostPort(r.RemoteAddr)
	return ip
}

// ToJSON converts a session to pretty-printed JSON for the admin panel
func (s Session) ToJSON() ([]byte, error) {
	return json.MarshalIndent(struct {
		ID         string `json:"id"`
		UserAgent  string `json:"user_agent"`
		IP         string `json:"ip"`
		LastActive string `json:"last_active"`
		CookieCount int   `json:"cookie_count"`
	}{
		ID:         s.ID,
		UserAgent:  s.UserAgent,
		IP:         s.IP,
		LastActive: s.LastActive.Format(time.RFC3339),
		CookieCount: len(strings.Split(s.Cookies, ";")),
	}, "", "  ")
}