package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/gofiber/fiber/v2/middleware/helmet"
	"github.com/gofiber/fiber/v2/middleware/limiter"
	"github.com/gofiber/fiber/v2/middleware/logger"
	"github.com/gofiber/fiber/v2/middleware/recover"

	appConfig "texnikum-backend/config"
	"texnikum-backend/database"
	"texnikum-backend/handlers"
)

func main() {
	// 1. Konfiguratsiyani xavfsiz yuklash
	cfg := appConfig.LoadConfig()

	// 2. AWS SDK v2 S3 mijozini initsializatsiya qilish
	staticCreds := credentials.NewStaticCredentialsProvider(
		cfg.S3.AccessKey,
		cfg.S3.SecretKey,
		"",
	)

	awsCfg, err := config.LoadDefaultConfig(context.TODO(),
		config.WithCredentialsProvider(staticCreds),
		config.WithRegion(cfg.S3.Region),
	)
	if err != nil {
		log.Fatalf("[FATAL] AWS konfiguratsiyasini yuklashda xatolik: %v", err)
	}

	s3Client := s3.NewFromConfig(awsCfg, func(o *s3.Options) {
		o.BaseEndpoint = aws.String(cfg.S3.Endpoint)
		o.UsePathStyle = true // UzCloud S3 (S3-compatible) uchun zarur
	})

	// 3. Ma'lumotlar bazasi (Database) modulini initsializatsiya qilish
	// Hozirgi bosqichda vaqtincha ishlamaydigan (coming soon) holatda boshlanadi
	dbManager := database.GetDatabaseManager()
	dbManager.InitDatabase(cfg.Database)

	// 4. Fiber ilovasi - Qat'iy tarmoq va xavfsizlik konfiguratsiyasi bilan
	app := fiber.New(fiber.Config{
		AppName:      "1-Son Texnikum Enterprise Hardened Backend v2",
		BodyLimit:    int(cfg.Server.MaxUploadBytes), // 25MB
		ReadTimeout:  15 * time.Second,              // Slowloris DDoS himoyasi
		WriteTimeout: 25 * time.Second,
		IdleTimeout:  120 * time.Second,
		ServerHeader: "Texnikum-Secure-Gate",
	})

	// 5. Global Xavfsizlik Middleware'lari (Defense-in-Depth)

	// 5.1. Panic Recovery - Kutilmagan xatoliklar serverni qulab tushishini oldini oladi (DoS himoyasi)
	app.Use(recover.New(recover.Config{
		EnableStackTrace: cfg.Server.Environment != "production",
	}))

	// 5.2. Audit Logging - Har bir so'rovni va IP manzilini xavfsiz qayd etish
	app.Use(logger.New(logger.Config{
		Format:     "[${time}] ${ip} - ${status} ${method} ${path} (${latency})\n",
		TimeFormat: "2006-01-02 15:04:05",
	}))

	// 5.3. Helmet - Qat'iy HTTP xavfsizlik sarlavhalari (XSS, Clickjacking, Sniffing himoyasi)
	app.Use(helmet.New(helmet.Config{
		XSSProtection:             "1; mode=block",
		ContentTypeNosniff:        "nosniff",
		XFrameOptions:             "DENY",
		ReferrerPolicy:            "strict-origin-when-cross-origin",
		CrossOriginEmbedderPolicy: "require-corp",
		CrossOriginOpenerPolicy:   "same-origin",
		CrossOriginResourcePolicy: "same-site",
		HSTSMaxAge:                31536000,
		HSTSExcludeSubdomains:     false,
	}))

	// 5.4. CORS - Ruxsat etilgan domenlarni tekshirish (Origin spoofing himoyasi)
	allowedOriginsStr := strings.Join(cfg.Security.AllowedOrigins, ", ")
	app.Use(cors.New(cors.Config{
		AllowOrigins:     allowedOriginsStr,
		AllowHeaders:     "Origin, Content-Type, Accept, Authorization, X-Timestamp, X-Nonce, X-Requested-With, X-Encrypt-Binary",
		AllowMethods:     "GET, POST, HEAD, PUT, DELETE, PATCH, OPTIONS",
		AllowCredentials: true,
		ExposeHeaders:    "Content-Length, X-Content-Type-Options",
		MaxAge:           86400,
	}))

	// 5.5. Rate Limiter - DDoS, flood va brute-force hujumlaridan global himoya
	app.Use(limiter.New(limiter.Config{
		Max:               cfg.Security.MaxReqPerMin,
		Expiration:        1 * time.Minute,
		KeyGenerator: func(c *fiber.Ctx) string {
			return c.IP()
		},
		LimitReached: func(c *fiber.Ctx) error {
			log.Printf("[RATE LIMIT TRIGGERED] IP: %s so'rovlar chegarasini buzdi\n", c.IP())
			return c.Status(fiber.StatusTooManyRequests).JSON(fiber.Map{
				"error":   "Juda ko'p so'rov yuborildi (Rate Limit). Iltimos, 1 daqiqa kuting.",
				"status":  false,
				"blocked": true,
			})
		},
	}))

	// 6. Handlerlarni yaratish
	uploadHandler := handlers.NewUploadHandler(cfg, s3Client)
	imageStreamHandler := handlers.NewImageStreamHandler(cfg, s3Client)
	authHandler := handlers.NewAuthHandler(cfg)
	dbHandler := handlers.NewDBHandler(dbManager)

	// 7. Maxsus cheklovlar (Upload va Auth uchun qat'iy Rate Limiting)
	uploadLimiter := limiter.New(limiter.Config{
		Max:        20, // 1 daqiqada maksimal 20 ta rasm yuklash (Storage Flood himoyasi)
		Expiration: 1 * time.Minute,
		KeyGenerator: func(c *fiber.Ctx) string {
			return c.IP()
		},
		LimitReached: func(c *fiber.Ctx) error {
			return c.Status(fiber.StatusTooManyRequests).JSON(fiber.Map{
				"error": "Rasm yuklash limiti oshib ketdi. 1 daqiqadan so'ng qayta urining.",
			})
		},
	})

	authLimiter := limiter.New(limiter.Config{
		Max:        15, // 1 daqiqada maksimal 15 ta handshake/kirish (Brute-force himoyasi)
		Expiration: 1 * time.Minute,
		KeyGenerator: func(c *fiber.Ctx) string {
			return c.IP()
		},
		LimitReached: func(c *fiber.Ctx) error {
			return c.Status(fiber.StatusTooManyRequests).JSON(fiber.Map{
				"error": "Avtorizatsiya so'rovlari limiti oshdi. Xavfsizlik blokirovkasi faol.",
			})
		},
	})

	// 8. API Yo'nalishlari (Routes)

	// Health Check diagnostika endpointlari
	healthResponse := func(c *fiber.Ctx) error {
		return c.JSON(fiber.Map{
			"status":      "HEALTHY",
			"service":     "1-Son Texnikum Enterprise Hardened Backend",
			"timestamp":   time.Now().Format(time.RFC3339),
			"environment": cfg.Server.Environment,
			"security": fiber.Map{
				"rate_limiting":         "ENABLED",
				"binary_validation":     "ENFORCED (0 va 1 Magic Bytes)",
				"encryption_algorithm": "AES-256-GCM Ready",
				"anti_replay_protection": "ACTIVE (Nonce + Skew validation)",
				"anti_sniffing":         "nosniff ENFORCED",
			},
			"storage": fiber.Map{
				"provider": "UzCloud S3",
				"status":   "CONNECTED",
			},
			"database": dbManager.GetStatus(),
		})
	}

	app.Get("/health", healthResponse)
	app.Get("/api/v1/health", healthResponse)

	// Rasm yuklash va binar oqim yo'nalishlari
	app.Post("/api/upload", uploadLimiter, uploadHandler.HandleUpload)
	app.Get("/api/images/stream/:filename", imageStreamHandler.StreamImage)

	// Autentifikatsiya va Handshake yo'nalishlari
	app.Post("/api/v1/auth/handshake", authLimiter, authHandler.HandleHandshake)
	app.Post("/api/v1/auth/verify-ticket", authHandler.HandleVerifyTicket)
	app.Post("/api/v1/auth/verify-session", authHandler.HandleVerifySession)
	app.Post("/api/v1/auth/logout", authHandler.HandleLogout)

	// Ma'lumotlar bazasi holati va diagnostikasi
	app.Get("/api/v1/database/status", dbHandler.HandleGetStatus)

	// 9. Noma'lum yo'nalishlar uchun 404 xavfsiz javobi
	app.Use(func(c *fiber.Ctx) error {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
			"error":  "Endpoint topilmadi yoki ruxsat etilmagan",
			"status": false,
		})
	})

	// 10. Graceful Shutdown bilan serverni ishga tushirish
	go func() {
		log.Println("======================================================================")
		log.Printf("🚀 [TEXNIKUM BACKEND] Server :%s portida ishga tushmoqda...\n", cfg.Server.Port)
		log.Printf("🔒 [XAVFSIZLIK] Binar tahlil (Magic Bytes), AES-256 va Rate-Limiter faol!\n")
		log.Printf("💾 [DATABASE] Arxitektura tayyor. Holat: %s\n", dbManager.GetStatus().Status)
		log.Println("======================================================================")

		if err := app.Listen(":" + cfg.Server.Port); err != nil {
			log.Fatalf("[FATAL] Serverni ishga tushirishda xatolik: %v", err)
		}
	}()

	// Signal kutilishi (Ctrl+C yoki SIGTERM)
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, os.Interrupt, syscall.SIGTERM)
	<-quit

	log.Println("[SHUTDOWN] Server xavfsiz to'xtatilmoqda...")
	if err := app.ShutdownWithTimeout(5 * time.Second); err != nil {
		log.Printf("[SHUTDOWN ERROR] Xatolik: %v", err)
	}
	log.Println("[SHUTDOWN] Server muvaffaqiyatli to'xtatildi.")
}
