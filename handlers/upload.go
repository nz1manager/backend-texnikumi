package handlers

import (
	"bytes"
	"fmt"
	"io"
	"log"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/gofiber/fiber/v2"

	"texnikum-backend/config"
	"texnikum-backend/security"
)

// UploadHandler rasm yuklash va binar xavfsizlik nazorati
type UploadHandler struct {
	cfg      *config.AppConfig
	s3Client *s3.Client
}

// NewUploadHandler yangi UploadHandler obyektini yaratadi
func NewUploadHandler(cfg *config.AppConfig, s3Client *s3.Client) *UploadHandler {
	return &UploadHandler{
		cfg:      cfg,
		s3Client: s3Client,
	}
}

// HandleUpload POST /api/upload endpointini boshqaradi
// 1. Faylni qabul qiladi
// 2. 0 va 1 binar darajasida (Magic Bytes va WebShell) tekshiradi
// 3. Xavfsiz, noaniq (non-predictable) nom yaratadi
// 4. Ixtiyoriy ravishda AES-256-GCM bilan binar shifrlaydi
// 5. UzCloud S3 ga joylashtiradi
func (h *UploadHandler) HandleUpload(c *fiber.Ctx) error {
	// So'rovdan 'image' faylini qabul qilish
	fileHeader, err := c.FormFile("image")
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error":  "Rasm fayli ('image') topilmadi yoki so'rov noto'g'ri",
			"code":   "FILE_MISSING",
			"status": false,
		})
	}

	// 1. Hajmni tekshirish
	if fileHeader.Size > h.cfg.Server.MaxUploadBytes {
		return c.Status(fiber.StatusRequestEntityTooLarge).JSON(fiber.Map{
			"error":  fmt.Sprintf("Rasm hajmi juda katta (maksimal: %d MB)", h.cfg.Server.MaxUploadBytes/(1024*1024)),
			"code":   "FILE_TOO_LARGE",
			"status": false,
		})
	}

	if h.cfg.S3.BucketName == "" {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error":  "Server sozlamalarida S3_BUCKET_NAME ko'rsatilmagan",
			"code":   "S3_CONFIG_ERROR",
			"status": false,
		})
	}

	// Faylni ochish va binar baytlarni xotiraga o'qish
	srcFile, err := fileHeader.Open()
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error":  "Faylni o'qishda xatolik yuz berdi",
			"detail": err.Error(),
		})
	}
	defer srcFile.Close()

	fileBytes, err := io.ReadAll(srcFile)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error":  "Fayl binar ma'lumotlarini o'qib bo'lmadi",
			"detail": err.Error(),
		})
	}

	// 2. 0 va 1 Binar Darajasidagi Qat'iy Tekshiruv (Magic Bytes va Antivirus/Webshell tahlil)
	valResult, err := security.ValidateImageBinary(fileBytes)
	if err != nil {
		log.Printf("[SECURITY ALERT] Buzg'unchi yoki noqonuniy fayl yuklashga urinish qaytarildi! Sabab: %v, Fayl: %s, Hajm: %d bayt\n",
			err, fileHeader.Filename, len(fileBytes))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error":  "Fayl xavfsizlik tekshiruvidan o'tmadi: " + err.Error(),
			"code":   "MALICIOUS_OR_INVALID_BINARY",
			"status": false,
		})
	}

	// 3. Path Traversal va xavfli belgilarni tozalash - Kriptografik nom hosil qilish
	secureFileName := security.SanitizeFilename(fileHeader.Filename, valResult.Extension)

	// 4. Shifrlash so'ralganmi? (X-Encrypt-Binary sarlavhasi yoki sozlama orqali)
	shouldEncrypt := c.Get("X-Encrypt-Binary") == "true" || c.Query("encrypt") == "true"
	dataToUpload := fileBytes
	contentType := valResult.MimeType

	if shouldEncrypt {
		encryptedBytes, encErr := security.EncryptBinary(fileBytes, h.cfg.Security.EncryptionKey)
		if encErr != nil {
			log.Printf("[CRYPTO ERROR] Rasmni shifrlashda xatolik: %v\n", encErr)
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": "Rasmni AES-256 orqali binar shifrlashda xatolik yuz berdi",
			})
		}
		dataToUpload = encryptedBytes
		contentType = "application/octet-stream"
		secureFileName = secureFileName + ".enc"
	}

	// 5. UzCloud S3 ga xavfsiz yuklash (PutObject)
	s3Key := fmt.Sprintf("uploads/%s", secureFileName)
	_, err = h.s3Client.PutObject(c.Context(), &s3.PutObjectInput{
		Bucket:      aws.String(h.cfg.S3.BucketName),
		Key:         aws.String(s3Key),
		Body:        bytes.NewReader(dataToUpload),
		ContentType: aws.String(contentType),
		Metadata: map[string]string{
			"sha256":      valResult.BinaryHash,
			"mime":        valResult.MimeType,
			"isEncrypted": fmt.Sprintf("%t", shouldEncrypt),
		},
	})
	if err != nil {
		log.Printf("S3 ga yuklashda xatolik: %v\n", err)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error":  "Faylni S3 ga yuklashda xatolik yuz berdi",
			"detail": err.Error(),
		})
	}

	// 6. To'g'ridan-to'g'ri va xavfsiz proxy oqim havolasini shakllantirish
	cleanEndpoint := strings.TrimRight(h.cfg.S3.Endpoint, "/")
	directURL := fmt.Sprintf("%s/%s/%s", cleanEndpoint, h.cfg.S3.BucketName, s3Key)
	secureStreamURL := fmt.Sprintf("/api/images/stream/%s", secureFileName)

	return c.JSON(fiber.Map{
		"url":             directURL,
		"secureStreamUrl": secureStreamURL,
		"key":             s3Key,
		"binaryHash":      valResult.BinaryHash,
		"mimeType":        valResult.MimeType,
		"bytes":           valResult.TotalBytes,
		"isEncrypted":     shouldEncrypt,
		"success":         true,
	})
}
