package security

import (
	"sync"
	"time"
)

// NonceManager Replay Attack (so'rovni qayta yuborib buzish) ga qarshi xotiradagi xavfsiz boshqaruvchi
type NonceManager struct {
	mu     sync.Mutex
	nonces map[string]time.Time
}

var globalNonceManager = &NonceManager{
	nonces: make(map[string]time.Time),
}

// GetNonceManager global NonceManager obyektini qaytaradi
func GetNonceManager() *NonceManager {
	return globalNonceManager
}

// VerifyAndStore tekshiradi: agar nonce avval ishlatilmagan bo'lsa, uni xotiraga yozadi va true qaytaradi.
// Agar nonce avval ishlatilgan bo'lsa (Replay Attack), false qaytaradi.
func (nm *NonceManager) VerifyAndStore(nonce string, ttl time.Duration) bool {
	if nonce == "" || len(nonce) < 8 {
		return false
	}

	nm.mu.Lock()
	defer nm.mu.Unlock()

	now := time.Now()

	// Eski eskirgan noncelarni tozalash
	for k, expiry := range nm.nonces {
		if now.After(expiry) {
			delete(nm.nonces, k)
		}
	}

	// Agar bu nonce allaqachon mavjud bo'lsa -> REPLAY ATTACK!
	if _, exists := nm.nonces[nonce]; exists {
		return false
	}

	// Yangi nonceni saqlash
	nm.nonces[nonce] = now.Add(ttl)
	return true
}

// ValidateTimestamp so'rov yuborilgan vaqt server vaqtidan ruxsat etilgan toleransdan oshib ketmaganligini tekshiradi (standart 90 soniya)
func ValidateTimestamp(clientUnixMs int64, maxSkewSeconds int64) bool {
	serverNow := time.Now().UnixMilli()
	diffMs := serverNow - clientUnixMs
	if diffMs < 0 {
		diffMs = -diffMs
	}
	return diffMs <= (maxSkewSeconds * 1000)
}
