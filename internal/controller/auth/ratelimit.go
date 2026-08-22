package auth

import (
	"sync"
	"time"
)

type LoginLimiter struct {
	mu       sync.Mutex
	attempts map[string]attempt
}

type attempt struct {
	Count     int
	BlockedTo time.Time
	UpdatedAt time.Time
}

func NewLoginLimiter() *LoginLimiter {
	return &LoginLimiter{attempts: make(map[string]attempt)}
}

func (l *LoginLimiter) Allow(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	item, ok := l.attempts[key]
	if !ok {
		return true
	}
	if now.Before(item.BlockedTo) {
		return false
	}
	if now.Sub(item.UpdatedAt) > 15*time.Minute {
		delete(l.attempts, key)
	}
	return true
}

func (l *LoginLimiter) Fail(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	item := l.attempts[key]
	if now.Sub(item.UpdatedAt) > 15*time.Minute {
		item.Count = 0
	}
	item.Count++
	item.UpdatedAt = now
	if item.Count >= 5 {
		item.BlockedTo = now.Add(time.Duration(item.Count-4) * time.Minute)
	}
	l.attempts[key] = item
}

func (l *LoginLimiter) Success(key string) {
	l.mu.Lock()
	delete(l.attempts, key)
	l.mu.Unlock()
}
