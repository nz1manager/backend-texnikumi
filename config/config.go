package config

import (
	"os"
	"strconv"
	"strings"
)

// AppConfig - Tizimning to'liq konfiguratsiyasi
type AppConfig struct {
	Server   ServerConfig
	S3       S3Config
	Security SecurityConfig
	Database DatabaseConfig
}

type ServerConfig struct {
	Port           string
	Environment    string // "production" yoki "development"
	MaxUploadBytes int64
}

type S3Config struct {
	Endpoint   string
	AccessKey  string
	SecretKey  string
	BucketName string
	Region     string
	UseSSL     bool
}

type SecurityConfig struct {
	AllowedOrigins []string
	EncryptionKey  string // 32 bayt AES-256 kalit (hex yoki string)
	APISecretKey   string // Ichki xavfsizlik tokeni
	TurnstileSecret string
	MaxReqPerMin   int
}

type DatabaseConfig struct {
	Enabled         bool
	Host            string
	Port            string
	User            string
	Password        string
	DBName          string
	SSLMode         string
	MaxOpenConns    int
	MaxIdleConns    int
	ConnMaxLifetime int // daqiqalarda
}

// LoadConfig muhit o'zgaruvchilarini o'qib xavfsiz konfiguratsiya obyektini qaytaradi
func LoadConfig() *AppConfig {
	port := os.Getenv("PORT")
	if port == "" {
		port = "10000"
	}

	env := os.Getenv("APP_ENV")
	if env == "" {
		env = "production"
	}

	// S3 sozlamalari
	s3Endpoint := os.Getenv("S3_ENDPOINT")
	if s3Endpoint == "" {
		s3Endpoint = "https://s3.uzcloud.uz"
	}

	s3Region := os.Getenv("S3_REGION")
	if s3Region == "" {
		s3Region = "us-east-1"
	}

	// Ruxsat berilgan domenlar (CORS xavfsizligi)
	allowedOriginsRaw := os.Getenv("ALLOWED_ORIGINS")
	var allowedOrigins []string
	if allowedOriginsRaw != "" {
		for _, o := range strings.Split(allowedOriginsRaw, ",") {
			o = strings.TrimSpace(o)
			if o != "" {
				allowedOrigins = append(allowedOrigins, o)
			}
		}
	} else {
		// Standart ishonchli domenlar
		allowedOrigins = []string{
			"http://localhost:5173",
			"http://localhost:3000",
			"https://1-sontexnikum.uz",
			"https://www.1-sontexnikum.uz",
			"https://backend-texnikumi.onrender.com",
		}
	}

	// Shifrlash kaliti (kamida 32 ta belgi bo'lishi lozim)
	encKey := os.Getenv("ENCRYPTION_KEY")
	if encKey == "" {
		// Standart xavfsiz zaxira kaliti (prod muhitda o'zgartirilishi shart)
		encKey = "1-son-texnikum-uzcloud-aes256-key-default-32b"
	}

	// Rate limiting sozlamasi
	rateLimitStr := os.Getenv("RATE_LIMIT_PER_MIN")
	rateLimit := 120
	if val, err := strconv.Atoi(rateLimitStr); err == nil && val > 0 {
		rateLimit = val
	}

	// Database sozlamalari (hozircha sukut bo'yicha o'chirilgan)
	dbEnabled := strings.ToLower(os.Getenv("DB_ENABLED")) == "true"
	dbPort := os.Getenv("DB_PORT")
	if dbPort == "" {
		dbPort = "5432"
	}
	dbSSL := os.Getenv("DB_SSLMODE")
	if dbSSL == "" {
		dbSSL = "require"
	}

	return &AppConfig{
		Server: ServerConfig{
			Port:           port,
			Environment:    env,
			MaxUploadBytes: 25 * 1024 * 1024, // 25 MB
		},
		S3: S3Config{
			Endpoint:   s3Endpoint,
			AccessKey:  os.Getenv("S3_ACCESS_KEY"),
			SecretKey:  os.Getenv("S3_SECRET_KEY"),
			BucketName: os.Getenv("S3_BUCKET_NAME"),
			Region:     s3Region,
			UseSSL:     true,
		},
		Security: SecurityConfig{
			AllowedOrigins:  allowedOrigins,
			EncryptionKey:   encKey,
			APISecretKey:    os.Getenv("API_SECRET_KEY"),
			TurnstileSecret: os.Getenv("TURNSTILE_SECRET_KEY"),
			MaxReqPerMin:    rateLimit,
		},
		Database: DatabaseConfig{
			Enabled:         dbEnabled,
			Host:            os.Getenv("DB_HOST"),
			Port:            dbPort,
			User:            os.Getenv("DB_USER"),
			Password:        os.Getenv("DB_PASSWORD"),
			DBName:          os.Getenv("DB_NAME"),
			SSLMode:         dbSSL,
			MaxOpenConns:    25,
			MaxIdleConns:    5,
			ConnMaxLifetime: 5,
		},
	}
}
