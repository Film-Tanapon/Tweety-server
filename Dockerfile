# ใช้ Image Go อย่างเป็นทางการ
FROM golang:1.25.7-alpine AS builder

WORKDIR /app

# ก๊อปปี้ไฟล์ go.mod และ go.sum (ถ้ามี)
COPY go.mod ./
# ถ้ามี go.sum ให้เอาคอมเมนต์ออก
# COPY go.sum ./ 
RUN go mod download

COPY . .

# Build แอป
RUN go build -o main .

# ใช้ Image เล็กๆ เพื่อรันแอป
FROM alpine:latest
WORKDIR /root/
COPY --from=builder /app/main .

# เปิด Port (Render จะจัดการต่อเอง)
EXPOSE 3000

CMD ["./main"]