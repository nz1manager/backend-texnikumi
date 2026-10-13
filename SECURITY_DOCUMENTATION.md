# 1-Son Texnikum — Backend Xavfsizlik va Ma'lumotlar Bazasi (Database) Qo'llanmasi

Ushbu backend tizimi eng yuqori darajadagi xavfsizlik (Enterprise-Grade Security) talablari asosida qayta ishlandi va mustahkamlandi. Quyida barcha xavfsizlik choralari, binar tahlil mexanizmi va kelajakdagi ma'lumotlar bazasi (Database) ulanish yo'riqnomasi bayon etilgan.

---

## 1. Bartaraf Etilgan Zaifliklar va Kuchaytirilgan Xavfsizlik (Security Hardening)

| Zaiflik turi / Hacker hujumi | Oldingi holat | Yangi himoya mexanizmi (Yechim) |
| :--- | :--- | :--- |
| **CORS Hujumi (Cross-Origin Exploit)** | Barcha domenlarga (`*`) ochiq edi | Faqat ruxsat etilgan domenlar (`ALLOWED_ORIGINS`: texnikum sayti va localhost) ruxsat etiladi. Ruxsatsiz saytlardan kelgan so'rovlar bloklanadi. |
| **Fayl orqali WebShell / Virus yuklash** | Faqat `c.FormFile` sarlavhasi o'qilar edi | **0 va 1 binar darajasida (Magic Bytes)** qat'iy tekshiruv. Faqat haqiqiy JPG, PNG, WEBP, GIF baytlari qabul qilinadi. Binar oqim ichida `<?php`, `<script>`, shell skriptlar aniqlansa darhol 400 xatosi bilan to'xtatiladi. |
| **Path Traversal (`../../`) Hujumi** | Foydalanuvchi yuborgan fayl nomi o'zgartirilmasdan ishlatilardi | Fayl nomi to'liq sanitarizatsiya qilinadi va kriptografik takrorlanmas xavfsiz nom (`tx-TIMESTAMP-RANDOMTOKEN.ext`) hosil qilinadi. |
| **DDoS va DoS (Serverni qulashga majburlash)** | Hech qanday so'rov chegarasi yo'q edi | **Fiber Limiter** orqali IP-manzilli Rate Limiting o'rnatildi: Global so'rovlar uchun daqiqasiga 120 ta, rasm yuklash uchun daqiqasiga 20 ta, avtorizatsiya uchun 15 ta limit. |
| **Slowloris va Tarmoq Qotib Qolishi** | Cheklovsiz kutish | Serverda `ReadTimeout: 15s`, `WriteTimeout: 25s`, `IdleTimeout: 120s` o'rnatildi. |
| **Replay Attack (So'rovni o'g'irlab qayta jo'natish)** | Himoyalanmagan edi | `X-Timestamp` (90 soniyalik darcha) va `X-Nonce` (bir martalik kriptografik token) xotirada tekshirilib, qayta jo'natilgan so'rovlar bloklanadi. |
| **MIME-Sniffing va XSS (Brauzer zaifligi)** | Xavfsizlik sarlavhalari yo'q edi | **Helmet middleware** qo'shildi: `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `HSTS`, `Content-Security-Policy`. |
| **Server Crash (Panic DoS)** | Bitta xatolik butun serverni to'xtatardi | `recover` middleware orqali barcha favqulodda vaziyatlar ushlab qolinadi va server to'xtab qolmaydi. |

---

## 2. 0 va 1 Binar Darajasidagi Tahlil va AES-256 Shifrlash

1. **Binar Magic Bytes Tekshiruvi:**
   - Faylning ilk baytlari (bit darajasida) tahlil qilinadi:
     - **JPEG:** `FF D8 FF`
     - **PNG:** `89 50 4E 47 0D 0A 1A 0A`
     - **WebP:** `52 49 46 46` (RIFF) va `57 45 42 50` (WEBP)
     - **GIF:** `GIF87a` / `GIF89a`
   - Noto'g'ri kengaytma berilgan har qanday soxta fayllar binar darajada fosh qilinadi va rad etiladi.

2. **AES-256-GCM Binar Shifrlash:**
   - Agar so'rovda `X-Encrypt-Binary: true` yuborilsa yoki `encrypt=true` bo'lsa:
     - Rasm baytlari xotirada 256-bitli simmetrik kalit bilan shifrlanadi.
     - S3 ga shifrlangan holatda saqlanadi (hech kim rasm tarkibini o'qiy olmaydi).
   - Saytga yuklash uchun maxsus oqim yo'li: `GET /api/images/stream/:filename`
     - Ushbu endpoint shifrlangan tasvirni xotirada xavfsiz deshifrlaydi va mijoz brauzeriga toza binar oqim (`image/jpeg`, `image/png`) va `nosniff` sarlavhalari bilan uzatadi.

---

## 3. Ma'lumotlar Bazasi (Database) Ulanish Arxitekturasi

Talabga muvofiq, ma'lumotlar bazasining ulanish poydevori (scaffolding) tayyorlandi va **xavfsizlik maqsadida vaqtincha ishlamaydigan (Coming Soon)** qilib qo'yildi.

### Hozirgi Holat:
- `DB_ENABLED=false` (sukut bo'yicha)
- Diagnostika endpointi: `GET /api/v1/database/status`
- Javob:
  ```json
  {
    "status": "coming_soon",
    "enabled": false,
    "message": "Ma'lumotlar bazasi (Database) ulanish arxitekturasi va xavfsizlik sozlamalari tayyorlandi. Tizim vaqtincha to'xtatilgan — tez orada ishga tushiriladi (Coming Soon).",
    "driver": "PostgreSQL / MySQL (GORM & pgx compatible)",
    "security_settings": {
      "ssl_mode": "require (TLS v1.3 majburiy)",
      "connection_pooling": "MaxOpen: 25, MaxIdle: 5",
      "conn_lifetime": "5 daqiqa (reconnect himoyasi)",
      "query_timeout": "5000ms (DoS va qotib qolishdan himoya)",
      "injection_protection": "Parameterized Prepared Statements majburiy"
    }
  }
  ```

### Kelajakda Databaseni Ulash Tartibi:
Ma'lumotlar bazasi serveri (PostgreSQL, Supabase yoki MySQL) tayyor bo'lgach:
1. `backend Go Lang/.env` fayliga quyidagi parametrlarni kiritasiz:
   ```env
   DB_ENABLED=true
   DB_HOST=sizning_postgres_host.uz
   DB_PORT=5432
   DB_USER=texnikum_admin
   DB_PASSWORD=juda_kuchli_va_shifrlangan_parol
   DB_NAME=texnikum_db
   DB_SSLMODE=require
   ```
2. `database/database.go` faylidagi tayyorlab qo'yilgan DSN va GORM/pgx ulanish qatorini izohdan chiqarasiz.

---

## 4. API Endpointlari Ro'yxati

| Metod | Manzil | Vazifasi | Xavfsizlik darajasi |
| :--- | :--- | :--- | :--- |
| `GET` | `/health` yoki `/api/v1/health` | Server, xotira, S3 va DB holati | Ochiq (Diagnostika) |
| `POST` | `/api/upload` | Rasmni binar tahlil qilib S3 ga yuklash | Qat'iy Rate Limit + 0/1 Magic Byte Validation + AES-256 |
| `GET` | `/api/images/stream/:filename` | Shifrlangan rasmlarni deshifrlab uzatish | Path Traversal himoyasi + Sniffing blokirovkasi |
| `POST` | `/api/v1/auth/handshake` | Admin kirish handshake | Nonce + Timestamp + Replay Attack himoyasi + HttpOnly Cookie |
| `POST` | `/api/v1/auth/verify-ticket` | Bir martalik chiptani tekshirish | Bir martalik tekshiruv (Burn on read) |
| `POST` | `/api/v1/auth/verify-session` | HttpOnly Cookie sessiyasini tekshirish | CSRF va XSS himoyasi |
| `POST` | `/api/v1/auth/logout` | Sessiyani tozalash | Xavfsiz chiqish |
| `GET` | `/api/v1/database/status` | Database ulanish holati | Himoyalangan diagnostika |

---

## 5. Kompilyatsiya va Ishga Tushirish Tekshiruvi

```bash
cd "backend Go Lang"
go mod tidy
go build -v .
./texnikum-backend
```
Docker orqali ishga tushirish uchun:
```bash
docker build -t texnikum-backend .
docker run -p 10000:10000 --env-file .env texnikum-backend
```
