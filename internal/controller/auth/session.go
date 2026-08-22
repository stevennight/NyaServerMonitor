package auth

import (
	"crypto/rand"
	"encoding/base64"
	"sync"
	"time"
)

type Session struct {
	ID        string
	UserID    int64
	Username  string
	CSRFToken string
	ExpiresAt time.Time
}

type Sessions struct {
	mu       sync.Mutex
	lifetime time.Duration
	items    map[string]Session
}

func NewSessions(lifetime time.Duration) *Sessions {
	if lifetime <= 0 {
		lifetime = 24 * time.Hour
	}
	return &Sessions{lifetime: lifetime, items: make(map[string]Session)}
}

func (s *Sessions) Create(userID int64, username string) (Session, error) {
	var raw [64]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return Session{}, err
	}
	session := Session{
		ID:        base64.RawURLEncoding.EncodeToString(raw[:32]),
		CSRFToken: base64.RawURLEncoding.EncodeToString(raw[32:]),
		UserID:    userID,
		Username:  username,
		ExpiresAt: time.Now().Add(s.lifetime),
	}
	s.mu.Lock()
	s.items[session.ID] = session
	s.mu.Unlock()
	return session, nil
}

func (s *Sessions) Get(id string) (Session, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	session, ok := s.items[id]
	if !ok {
		return Session{}, false
	}
	if time.Now().After(session.ExpiresAt) {
		delete(s.items, id)
		return Session{}, false
	}
	return session, true
}

func (s *Sessions) Delete(id string) {
	s.mu.Lock()
	delete(s.items, id)
	s.mu.Unlock()
}
