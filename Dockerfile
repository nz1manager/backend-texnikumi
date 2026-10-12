# 1-bosqich: Builder (Loyiha go.mod versiyasiga mos holda golang:1.24-alpine)
FROM golang:1.24-alpine AS builder

WORKDIR /app

# Bog'liqliklarni keshlashtirish uchun mod fayllarini ko'chirish
COPY go.mod go.sum ./
RUN go mod download

# Barcha kodlarni ko'chirish
COPY . .

# Statik binar fayl qilib kompilyatsiya qilish
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-w -s" -o main .

# 2-bosqich: Final (Minimal va yengil alpine tasviri)
FROM alpine:latest

# UzCloud S3 ga HTTPS orqali xavfsiz ulanish uchun sertifikatlar
RUN apk --no-cache add ca-certificates

WORKDIR /app

# Builder bosqichidan tayyor binar faylni ko'chirib olish
COPY --from=builder /app/main .

# Render.com kutadigan standart port
EXPOSE 10000

# Serverni ishga tushirish
CMD ["./main"]
