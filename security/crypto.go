package security

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
)

var (
	ErrInvalidCiphertext = errors.New("shifrlangan binar ma'lumot noto'g'ri yoki buzilgan")
	ErrInvalidKey        = errors.New("shifrlash kaliti yaroqsiz")
)

// DeriveKey berilgan maxfiy so'zdan AES-256 uchun 32 baytlik kriptografik kalit yasaydi
func DeriveKey(secret string) []byte {
	hash := sha256.Sum256([]byte(secret))
	return hash[:]
}

// EncryptBinary - Binar faylni (masalan rasm yoki hujjatni) AES-256-GCM orqali shifrlaydi.
// Natija: Nonce (12 bayt) + Shifrlangan Binar Ma'lumot + Autentifikatsiya Teg (16 bayt)
func EncryptBinary(plainBytes []byte, secret string) ([]byte, error) {
	key := DeriveKey(secret)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	// Seal: nonce + ciphertext + tag
	ciphertext := gcm.Seal(nonce, nonce, plainBytes, nil)
	return ciphertext, nil
}

// DecryptBinary - AES-256-GCM bilan shifrlangan binar ma'lumotni asliga qaytaradi
func DecryptBinary(cipherBytes []byte, secret string) ([]byte, error) {
	key := DeriveKey(secret)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	if len(cipherBytes) < nonceSize {
		return nil, ErrInvalidCiphertext
	}

	nonce, ciphertext := cipherBytes[:nonceSize], cipherBytes[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, ErrInvalidCiphertext
	}

	return plaintext, nil
}

// HashBinarySHA256 binar baytlarning kriptografik xeshini qaytaradi (SHA-256)
func HashBinarySHA256(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// GenerateSecureToken tasodifiy kriptografik xavfsiz token (hex) generatsiya qiladi
func GenerateSecureToken(byteLength int) string {
	b := make([]byte, byteLength)
	if _, err := rand.Read(b); err != nil {
		return hex.EncodeToString(DeriveKey(string(b)))
	}
	return hex.EncodeToString(b)
}
