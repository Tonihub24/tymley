package main

import (
	"crypto/sha256"
	"encoding/hex"
	"sync"
	"time"
)

type EventFingerprint struct {
	LastSeen time.Time
}

var (
	dedupeCache = make(map[string]EventFingerprint)
	dedupeMutex sync.Mutex
)

func fingerprintEvent(e Event) string {

	raw :=
		e.Type + "|" +
			e.Path + "|" +
			e.Message

	hash := sha256.Sum256([]byte(raw))

	return hex.EncodeToString(hash[:])
}

func AllowEvent(e Event) bool {

	dedupeMutex.Lock()
	defer dedupeMutex.Unlock()

	fp := fingerprintEvent(e)

	now := time.Now()

	if existing, ok := dedupeCache[fp]; ok {

		// duplicate within 2 seconds
		if now.Sub(existing.LastSeen) < 2*time.Second {
			return false
		}
	}

	dedupeCache[fp] = EventFingerprint{
		LastSeen: now,
	}

	return true
}
