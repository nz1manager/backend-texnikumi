package handlers

import (
	"github.com/gofiber/fiber/v2"

	"texnikum-backend/database"
)

// DBHandler ma'lumotlar bazasi diagnostikasi va holatini uzatuvchi handler
type DBHandler struct {
	dbManager *database.DatabaseManager
}

// NewDBHandler yangi DBHandler obyektini yaratadi
func NewDBHandler(dbManager *database.DatabaseManager) *DBHandler {
	return &DBHandler{
		dbManager: dbManager,
	}
}

// HandleGetStatus GET /api/v1/database/status
// Ma'lumotlar bazasi holati va xavfsizlik ulanish sozlamalarini qaytaradi
func (h *DBHandler) HandleGetStatus(c *fiber.Ctx) error {
	statusInfo := h.dbManager.GetStatus()
	return c.JSON(statusInfo)
}
