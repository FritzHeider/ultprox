package proxy

import (
	"database/sql"
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

// SessionManager handles session operations
type SessionManager struct {
	db   *sql.DB
	lock sync.RWMutex
}