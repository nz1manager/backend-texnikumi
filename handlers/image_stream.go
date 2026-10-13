package handlers

import (
	"fmt"
	"io"
	"log"
	"path/filepath"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/gofiber/fiber/v2"

	"texnikum-backend/config"
	"texnikum-backend/security"
)

// ImageStreamHandler xavfsiz shifrlangan binar tasvirlarni saytga oqim sifatida uzatuvchi
type ImageStreamHandler struct {
	cfg      *config.AppConfig
	s3Client *s3.Client
}

// NewImageStreamHandler yangi oqim handlerini yaratadi
func NewImageStreamHandler(cfg *config.AppConfig, s3Client *s3.Client) *ImageStreamHandler {
	return &ImageStreamHandler{
		cfg:      cfg,
		s3Client: s3Client,
	}
}

// StreamImage GET /api/images/stream/:filename
// 1. Fayl nomini path traversal hujumlaridan tozalaydi
// 2. UzCloud S3 dan binar oqimni yuklab oladi
// 3. Agar rasm AES-256 bilan shifrlangan bo'lsa, xotirada tezkor deshifrlaydi
// 4. Qat'iy xavfsizlik sarlavhalari bilan mijozga (brauzerga) 0 va 1 binar oqim sifatida uzatadi
func (h *ImageStreamHandler) StreamImage(c *fiber.Ctx) error {
	rawFilename := c.Params("filename")
	if rawFilename == "" {
		return c.Status(fiber.StatusBadRequest).SendString("Fayl nomi ko'rsatilmadi")
	}

	// 1. Path Traversal (../../) hujumlaridan qat'iy tozalash
	cleanFilename := filepath.Base(rawFilename)
	cleanFilename = strings.ReplaceAll(cleanFilename, "..", "")
	cleanFilename = strings.ReplaceAll(cleanFilename, "/", "")
	cleanFilename = strings.ReplaceAll(cleanFilename, "\\", "")

	s3Key := fmt.Sprintf("uploads/%s", cleanFilename)

	// 2. S3 dan obyektni olish
	resp, err := h.s3Client.GetObject(c.Context(), &s3.GetObjectInput{
		Bucket: aws.String(h.cfg.S3.BucketName),
		Key:    aws.String(s3Key),
	})
	if err != nil {
		log.Printf("[IMAGE STREAM] Rasm topilmadi yoki S3 xatosi: %v (Key: %s)\n", err, s3Key)
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
			"error":  "Rasm topilmadi yoki kirish taqiqlangan",
			"status": false,
		})
	}
	defer resp.Body.Close()

	// 3. Binar ma'lumotni o'qish
	rawBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Binar oqimni o'qishda xatolik",
		})
	}

	// 4. Agar fayl shifrlangan bo'lsa (.enc kengaytma yoki metadata) -> AES-256-GCM deshifrlash
	isEncrypted := strings.HasSuffix(cleanFilename, ".enc")
	finalBytes := rawBytes

	if isEncrypted {
		decrypted, decErr := security.DecryptBinary(rawBytes, h.cfg.Security.EncryptionKey)
		if decErr != nil {
			log.Printf("[SECURITY] Shifrlangan binar rasmni ochishda xatolik: %v\n", decErr)
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": "Shifrlangan rasmni deshifrlab bo'lmadi",
			})
		}
		finalBytes = decrypted
	}

	// 5. Binar tahlil orqali haqiqiy MIME turini aniqlash
	valResult, err := security.ValidateImageBinary(finalBytes)
	mimeType := "image/jpeg"
	if err == nil && valResult != nil {
		mimeType = valResult.MimeType
	}

	// 6. Qat'iy Xavfsizlik sarlavhalari (MIME Sniffing va XSS himoyasi)
	c.Set("Content-Type", mimeType)
	c.Set("X-Content-Type-Options", "nosniff")
	c.Set("Content-Security-Policy", "default-src 'none'")
	c.Set("Cache-Control", "public, max-age=86400, stale-while-revalidate=604800")
	c.Set("X-Frame-Options", "DENY")

	// 7. 0 va 1 binar oqimni brauzerga yuborish
	return c.Send(finalBytes)
}
