package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
)

func main() {
	// 1. Muhit o'zgaruvchilarini o'qish
	s3Endpoint := os.Getenv("S3_ENDPOINT")
	if s3Endpoint == "" {
		s3Endpoint = "https://s3.uzcloud.uz"
	}
	s3AccessKey := os.Getenv("S3_ACCESS_KEY")
	s3SecretKey := os.Getenv("S3_SECRET_KEY")
	s3BucketName := os.Getenv("S3_BUCKET_NAME")
	s3Region := os.Getenv("S3_REGION")
	if s3Region == "" {
		s3Region = "us-east-1"
	}

	// 2. AWS SDK v2 S3 mijozini sozlash
	staticCreds := credentials.NewStaticCredentialsProvider(s3AccessKey, s3SecretKey, "")

	cfg, err := config.LoadDefaultConfig(context.TODO(),
		config.WithCredentialsProvider(staticCreds),
		config.WithRegion(s3Region),
	)
	if err != nil {
		log.Fatalf("AWS konfiguratsiyasini yuklashda xatolik: %v", err)
	}

	s3Client := s3.NewFromConfig(cfg, func(o *s3.Options) {
		o.BaseEndpoint = aws.String(s3Endpoint)
		o.UsePathStyle = true // UzCloud S3 (S3-compatible) uchun zarur
	})

	// 3. Fiber ilovasini initsializatsiya qilish
	app := fiber.New(fiber.Config{
		BodyLimit: 25 * 1024 * 1024, // Maksimal yuklanadigan fayl hajmi: 25MB
	})

	// CORS middleware sozlamalari
	app.Use(cors.New(cors.Config{
		AllowOrigins: "*",
		AllowHeaders: "Origin, Content-Type, Accept, Authorization",
		AllowMethods: "GET, POST, HEAD, PUT, DELETE, PATCH, OPTIONS",
	}))

	// Health check endpointi
	app.Get("/health", func(c *fiber.Ctx) error {
		return c.SendString("OK")
	})

	// POST /api/upload - Rasmni UzCloud S3 ga yuklash
	app.Post("/api/upload", func(c *fiber.Ctx) error {
		// So'rovdan 'image' faylini qabul qilish
		fileHeader, err := c.FormFile("image")
		if err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error": "Rasm fayli ('image') topilmadi yoki noto'g'ri yuborilgan",
			})
		}

		if s3BucketName == "" {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": "Server sozlamalarida S3_BUCKET_NAME ko'rsatilmagan",
			})
		}

		// Faylni o'qish uchun ochish
		file, err := fileHeader.Open()
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": "Faylni ochishda xatolik yuz berdi",
			})
		}
		defer file.Close()

		// Takrorlanmas fayl nomi: timestamp-filename
		fileName := fmt.Sprintf("%d-%s", time.Now().Unix(), fileHeader.Filename)

		// Faylning Content-Type qiymatini olish
		contentType := fileHeader.Header.Get("Content-Type")
		if contentType == "" {
			contentType = "application/octet-stream"
		}

		// S3 ga PutObject orqali yuklash
		_, err = s3Client.PutObject(c.Context(), &s3.PutObjectInput{
			Bucket:      aws.String(s3BucketName),
			Key:         aws.String(fileName),
			Body:        file,
			ContentType: aws.String(contentType),
		})
		if err != nil {
			log.Printf("S3 ga yuklashda xatolik: %v\n", err)
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error":  "Faylni S3 ga yuklashda xatolik yuz berdi",
				"detail": err.Error(),
			})
		}

		// To'g'ridan-to'g'ri havola yasash: https://s3.uzcloud.uz/BUCKET_NOMI/FAYL_NOMI
		cleanEndpoint := strings.TrimRight(s3Endpoint, "/")
		fileURL := fmt.Sprintf("%s/%s/%s", cleanEndpoint, s3BucketName, fileName)

		return c.JSON(fiber.Map{
			"url": fileURL,
		})
	})

	// 4. Serverni ishga tushirish (PORT env yoki 10000)
	port := os.Getenv("PORT")
	if port == "" {
		port = "10000"
	}

	log.Printf("Server %s-portda ishga tushmoqda...\n", port)
	if err := app.Listen(":" + port); err != nil {
		log.Fatalf("Serverni ishga tushirishda xatolik: %v", err)
	}
}
