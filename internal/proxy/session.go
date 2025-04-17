package proxy

import (
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

// SessionManager handles all session operations
type SessionManager struct {
	db   *sql.DB
	lock sync.RWMutex
}

// NewSessionManager creates a new session manager instance
func NewSessionManager(db *sql.DB) *SessionManager {
	return &SessionManager{db: db}
}

// saveSessionToDB stores session in database (called from updateSession)
func saveSessionToDB(session Session) error {
	if db == nil {
		return errors.New("database not initialized")
	}

	_, err := db.Exec(`
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
		log.Printf("Failed to save session: %v", err)
		return err
	}
	return nil
}

// getRealIP extracts the real IP from request considering proxies
func getRealIP(r *http.Request) string {
	if ip := r.Header.Get("X-Forwarded-For"); ip != "" {
		return strings.Split(ip, ",")[0]
	}
	if ip := r.Header.Get("X-Real-IP"); ip != "" {
		return ip
	}
	host, _, _ := net.SplitHostPort(r.RemoteAddr)
	return host
}

// getAllSessions returns all captured sessions from database
func getAllSessions() ([]Session, error) {
	rows, err := db.Query(`
		SELECT id, cookies, user_agent, ip, last_active, metadata 
		FROM sessions ORDER BY last_active DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var sessions []Session
	for rows.Next() {
		var s Session
		var lastActive string
		err := rows.Scan(
			&s.ID,
			&s.Cookies,
			&s.UserAgent,
			&s.IP,
			&lastActive,
			&s.Metadata,
		)
		if err != nil {
			return nil, err
		}
		
		s.LastActive, _ = time.Parse(time.RFC3339, lastActive)
		sessions = append(sessions, s)
	}
	return sessions, nil
}

// getSessionByID retrieves a specific session
func getSessionByID(id string) (Session, error) {
	var s Session
	var lastActive string
	
	err := db.QueryRow(`
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
		return Session{}, err
	}
	
	s.LastActive, _ = time.Parse(time.RFC3339, lastActive)
	return s, nil
}

// cleanOldSessions removes sessions older than specified duration
func cleanOldSessions(maxAge time.Duration) {
	_, err := db.Exec(`
		DELETE FROM sessions 
		WHERE last_active < ?`,
		time.Now().Add(-maxAge).Format(time.RFC3339),
	)
	
	if err != nil {
		log.Printf("Failed to clean old sessions: %v", err)
	}
}

// sessionToJSON converts session to JSON for admin panel
func sessionToJSON(s Session) ([]byte, error) {
	return json.MarshalIndent(struct {
		ID         string `json:"id"`
		UserAgent  string `json:"user_agent"`
		IP         string `json:"ip"`
		LastActive string `json:"last_active"`
		Cookies    int    `json:"cookie_count"`
	}{
		ID:         s.ID,
		UserAgent:  s.UserAgent,
		IP:         s.IP,
		LastActive: s.LastActive.Format(time.RFC3339),
		Cookies:    len(strings.Split(s.Cookies, ";")),
	}, "", "  ")
}