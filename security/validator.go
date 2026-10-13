package security

import (
	"bytes"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"time"
)

var (
	ErrFileTooEmpty       = errors.New("fayl bo'sh yoki binar ma'lumot yetarli emas")
	ErrUnsupportedFormat  = errors.New("fayl formati qabul qilinmadi (faqat haqiqiy JPG, PNG, WEBP ruxsat etilgan)")
	ErrMaliciousSignature = errors.New("xavfli binar kod yoki skript aniqlandi (xavfsizlik himoyasi)")
)

// ImageValidationResult rasm tekshiruv natijasi
type ImageValidationResult struct {
	IsValid     bool
	MimeType    string
	Extension   string
	BinaryHash  string
	TotalBytes  int
}

// ValidateImageBinary binar oqimni (0 va 1 baytlarni) qat'iy tekshiradi:
// 1. Magic bytes (Binar imzo) tekshiruvi
// 2. MIME mosligi
// 3. Xavfli skript va polimorfik kodlar yo'qligini tekshirish
func ValidateImageBinary(data []byte) (*ImageValidationResult, error) {
	if len(data) < 12 {
		return nil, ErrFileTooEmpty
	}

	// 1. Bayt darajasida Magic Number (Binar imzo) tekshiruvi:
	var mimeType string
	var extension string

	// JPEG / JPG binar belgisi: FF D8 FF
	if len(data) >= 3 && data[0] == 0xFF && data[1] == 0xD8 && data[2] == 0xFF {
		mimeType = "image/jpeg"
		extension = ".jpg"
	} else if len(data) >= 8 &&
		// PNG binar belgisi: 89 50 4E 47 0D 0A 1A 0A
		data[0] == 0x89 && data[1] == 0x50 && data[2] == 0x4E && data[3] == 0x47 &&
		data[4] == 0x0D && data[5] == 0x0A && data[6] == 0x1A && data[7] == 0x0A {
		mimeType = "image/png"
		extension = ".png"
	} else if len(data) >= 12 &&
		// WebP binar belgisi: "RIFF" (52 49 46 46) ... "WEBP" (57 45 42 50)
		data[0] == 0x52 && data[1] == 0x49 && data[2] == 0x46 && data[3] == 0x46 &&
		data[8] == 0x57 && data[9] == 0x45 && data[10] == 0x42 && data[11] == 0x50 {
		mimeType = "image/webp"
		extension = ".webp"
	} else if len(data) >= 6 &&
		// GIF binar belgisi: GIF87a yoki GIF89a
		(string(data[:6]) == "GIF87a" || string(data[:6]) == "GIF89a") {
		mimeType = "image/gif"
		extension = ".gif"
	} else {
		return nil, ErrUnsupportedFormat
	}

	// 2. Ichki xavfli kod / Polyglot / WebShell imzolarini binar darajada skanerlash
	// Hackerlar rasm ichiga PHP, JS yoki shell kodlarini yashirishi mumkin
	sampleSize := len(data)
	if sampleSize > 4096 {
		sampleSize = 4096
	}
	headerSample := bytes.ToLower(data[:sampleSize])

	maliciousPatterns := [][]byte{
		[]byte("<?php"),
		[]byte("<script"),
		[]byte("javascript:"),
		[]byte("onload="),
		[]byte("onerror="),
		[]byte("<!doctype html"),
		[]byte("<html"),
		[]byte("eval("),
		[]byte("base64_decode("),
		[]byte("/bin/sh"),
		[]byte("/bin/bash"),
		[]byte("cmd.exe"),
	}

	for _, pattern := range maliciousPatterns {
		if bytes.Contains(headerSample, pattern) {
			return nil, ErrMaliciousSignature
		}
	}

	hash := HashBinarySHA256(data)

	return &ImageValidationResult{
		IsValid:    true,
		MimeType:   mimeType,
		Extension:  extension,
		BinaryHash: hash,
		TotalBytes: len(data),
	}, nil
}

// SanitizeFilename - Path Traversal (../) va buzg'unchi belgilardan tozalangan,
// xavfsiz va takrorlanmas fayl nomini hosil qiladi
func SanitizeFilename(originalFilename string, trustedExtension string) string {
	// Original yo'lni olib tashlash (faqat fayl nomining o'zi)
	cleanName := filepath.Base(originalFilename)

	// Xavfli belgilarni almashtirish
	cleanName = strings.ReplaceAll(cleanName, " ", "-")
	cleanName = strings.ReplaceAll(cleanName, "/", "")
	cleanName = strings.ReplaceAll(cleanName, "\\", "")
	cleanName = strings.ReplaceAll(cleanName, "..", "")
	cleanName = strings.ReplaceAll(cleanName, "\x00", "") // Null byte injection

	// Tasodifiy 8 baytlik token
	randToken := GenerateSecureToken(4)
	timestamp := time.Now().UnixNano()

	// Agar trustedExtension berilgan bo'lsa, xavfsiz kengaytmani majburiy o'rnatamiz
	ext := trustedExtension
	if ext == "" {
		ext = filepath.Ext(cleanName)
		if ext == "" {
			ext = ".bin"
		}
	}
	if !strings.HasPrefix(ext, ".") {
		ext = "." + ext
	}

	return fmt.Sprintf("tx-%d-%s%s", timestamp, randToken, strings.ToLower(ext))
}
