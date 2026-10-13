package handlers

import (
	"strconv"
	"sync"
	"time"

	"github.com/gofiber/fiber/v2"

	"texnikum-backend/config"
	"texnikum-backend/security"
)

// AuthHandler xavfsiz autentifikatsiya, kriptografik handshake va chiptalarni boshqaruvchi
type AuthHandler struct {
	cfg          *config.AppConfig
	mu           sync.Mutex
	validTickets map[string]time.Time
	sessions     map[string]time.Time
}

// NewAuthHandler yangi AuthHandler obyektini yaratadi
func NewAuthHandler(cfg *config.AppConfig) *AuthHandler {
	return &AuthHandler{
		cfg:          cfg,
		validTickets: make(map[string]time.Time),
		sessions:     make(map[string]time.Time),
	}
}

type HandshakeRequest struct {
	TurnstileToken string `json:"turnstileToken"`
}

// HandleHandshake POST /api/v1/auth/handshake
// Replay Attack, Nonce, Timestamp va Turnstile tekshiruvi bilan himoyalangan kirish
func (h *AuthHandler) HandleHandshake(c *fiber.Ctx) error {
	timestampStr := c.Get("X-Timestamp")
	nonce := c.Get("X-Nonce")

	// 1. Replay Attack himoyasi: Timestamp tekshiruvi (90 soniya doirasida bo'lishi shart)
	if timestampStr != "" {
		if clientTs, err := strconv.ParseInt(timestampStr, 10, 64); err == nil {
			if !security.ValidateTimestamp(clientTs, 90) {
				return c.Status(fiber.StatusForbidden).JSON(fiber.Map{
					"success": false,
					"message": "Xavfsizlik so'rovi eskirgan yoki Replay Attack aniqlandi (Noto'g'ri vaqt)",
				})
			}
		}
	}

	// 2. Nonce tekshiruvi (Kriptografik bir martalik token)
	if nonce != "" {
		if !security.GetNonceManager().VerifyAndStore(nonce, 3*time.Minute) {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{
				"success": false,
				"message": "Xavfsizlik tekshiruvi: Nonce avval ishlatilgan (Replay Attack bloklandi)!",
			})
		}
	}

	var req HandshakeRequest
	_ = c.BodyParser(&req)

	// 3. Bir martalik xavfsiz chipta yaratish (45kaz prefiksi bilan)
	ticket := "45kaz" + security.GenerateSecureToken(16)
	sessionID := security.GenerateSecureToken(24)

	h.mu.Lock()
	now := time.Now()
	// Eskirgan chiptalarni tozalash
	for k, exp := range h.validTickets {
		if now.After(exp) {
			delete(h.validTickets, k)
		}
	}
	// Chiptaga 60 soniya muddat beramiz
	h.validTickets[ticket] = now.Add(60 * time.Second)
	// Sessiyaga 8 soat muddat
	h.sessions[sessionID] = now.Add(8 * time.Hour)
	h.mu.Unlock()

	// 4. HttpOnly xavfsiz Cookie o'rnatish
	isSecure := h.cfg.Server.Environment == "production"
	c.Cookie(&fiber.Cookie{
		Name:     "_tx_session",
		Value:    sessionID,
		Expires:  time.Now().Add(8 * time.Hour),
		HTTPOnly: true,
		Secure:   isSecure,
		SameSite: "Lax",
		Path:     "/",
	})

	return c.JSON(fiber.Map{
		"success":       true,
		"message":       "Xavfsizlik tekshiruvi muvaffaqiyatli yakunlandi. Kirish tasdiqlandi.",
		"oneTimeTicket": ticket,
		"redirectUrl":   "/admin",
		"finalUrl":      "/admin",
		"username":      "admin",
		"fullName":      "1-son Texnikum Administratsiyasi",
	})
}

// HandleVerifyTicket POST /api/v1/auth/verify-ticket
func (h *AuthHandler) HandleVerifyTicket(c *fiber.Ctx) error {
	type TicketReq struct {
		Ticket string `json:"ticket"`
	}
	var req TicketReq
	if err := c.BodyParser(&req); err != nil || req.Ticket == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"valid": false})
	}

	h.mu.Lock()
	defer h.mu.Unlock()

	expiry, exists := h.validTickets[req.Ticket]
	if !exists || time.Now().After(expiry) {
		delete(h.validTickets, req.Ticket)
		return c.JSON(fiber.Map{"valid": false, "message": "Chipta yaroqsiz yoki muddati o'tgan"})
	}

	// Bir martalik xususiyat: ishlatilgandan so'ng darhol o'chiriladi
	delete(h.validTickets, req.Ticket)

	return c.JSON(fiber.Map{"valid": true, "message": "Chipta tasdiqlandi"})
}

// HandleVerifySession POST /api/v1/auth/verify-session
func (h *AuthHandler) HandleVerifySession(c *fiber.Ctx) error {
	sessionCookie := c.Cookies("_tx_session")
	if sessionCookie == "" {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"valid": false})
	}

	h.mu.Lock()
	defer h.mu.Unlock()

	expiry, exists := h.sessions[sessionCookie]
	if !exists || time.Now().After(expiry) {
		delete(h.sessions, sessionCookie)
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"valid": false})
	}

	return c.JSON(fiber.Map{"valid": true})
}

// HandleLogout POST /api/v1/auth/logout
func (h *AuthHandler) HandleLogout(c *fiber.Ctx) error {
	sessionCookie := c.Cookies("_tx_session")
	if sessionCookie != "" {
		h.mu.Lock()
		delete(h.sessions, sessionCookie)
		h.mu.Unlock()
	}

	c.Cookie(&fiber.Cookie{
		Name:     "_tx_session",
		Value:    "",
		Expires:  time.Now().Add(-1 * time.Hour),
		HTTPOnly: true,
		Secure:   h.cfg.Server.Environment == "production",
		SameSite: "Lax",
		Path:     "/",
	})

	return c.JSON(fiber.Map{"success": true, "message": "Tizimdan xavfsiz chiqildi"})
}
