package main

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"math/rand"
	"net/http"
	"net/smtp"
	"os"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/gorilla/websocket"
	"github.com/lib/pq"
	"golang.org/x/crypto/bcrypt"
	"google.golang.org/api/idtoken"
)

type User struct {
	ID              int       `json:"id"`
	Email           string    `json:"email"`
	Username        string    `json:"username"`
	ProfileImageURL string    `json:"profile_image_url"`
	CoverImageURL   string    `json:"cover_image_url"`
	CreatedAt       time.Time `json:"created_at"`
}

type PostFeed struct {
	PostID          int       `json:"post_id"`
	UserID          int       `json:"user_id"`
	Username        string    `json:"username"`
	ProfileImageURL string    `json:"profile_image_url"`
	Content         string    `json:"content"`
	ImageURLs       []string  `json:"image_urls"`
	ParentPostID    *int      `json:"parent_post_id"`
	LikeCount       int       `json:"like_count"`
	CreatedAt       time.Time `json:"created_at"`
}

type Message struct {
	ID         int       `json:"id"`
	SenderID   int       `json:"sender_id"`
	ReceiverID int       `json:"receiver_id"`
	Content    string    `json:"content"`
	ImageURL   *string   `json:"image_url"`
	IsRead     bool      `json:"is_read"`
	CreatedAt  time.Time `json:"created_at"`
}

type ActionRequest struct {
	Action     string   `json:"action"`
	UserID     int      `json:"user_id"`
	ReceiverID int      `json:"receiver_id,omitempty"`
	PostID     int      `json:"post_id,omitempty"`
	Content    string   `json:"content,omitempty"`
	ImageURLs  []string `json:"image_urls,omitempty"`
	ImageURL   string   `json:"image_url,omitempty"`
	Token      string   `json:"token,omitempty"`
	Email      string   `json:"email,omitempty"`
	Username   string   `json:"username,omitempty"`
	Password   string   `json:"password,omitempty"`
	OTP        string   `json:"otp,omitempty"`
}

var jwtSecretKey = os.Getenv("JWT_SECRET")
var googleClientID = os.Getenv("GOOGLE_CLIENT_ID")

var otpStorage = make(map[string]string)
var userConnections = make(map[int]*websocket.Conn) // 🟢 WebSocket Conn
var mutex = &sync.Mutex{}
var db *sql.DB

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool {
		return true // ยอมรับการเชื่อมต่อจากทุกโดเมน (เพื่อให้ Flutter เชื่อมต่อได้)
	},
}

func main() {
	connStr := os.Getenv("DB_URL")
	var err error
	db, err = sql.Open("postgres", connStr)
	if err != nil {
		log.Fatal("Error opening database:", err)
	}
	defer db.Close()

	if err = db.Ping(); err != nil {
		log.Fatal("Cannot connect to Database:", err)
	}
	fmt.Println("✅ Connected to Database successfully!")

	port := os.Getenv("PORT")
	if port == "" {
		port = "3000"
	}

	http.HandleFunc("/", handleConnections)

	fmt.Println("🚀 WebSocket Server Started on port", port, "...")
	log.Fatal(http.ListenAndServe("0.0.0.0:"+port, nil))
}

func handleConnections(w http.ResponseWriter, r *http.Request) {
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		fmt.Println("WebSocket Upgrade Error:", err)
		return
	}

	var loggedInUserID int
	defer func() {
		conn.Close()
		if loggedInUserID != 0 {
			mutex.Lock()
			delete(userConnections, loggedInUserID)
			mutex.Unlock()
			fmt.Printf("User %d disconnected\n", loggedInUserID)
		}
	}()

	sendHistoryToClient(conn)

	for {
		var req ActionRequest
		err := conn.ReadJSON(&req)
		if err != nil {
			// ถ้ามี Error แปลว่า Client ปิดแอพ หรือเน็ตหลุด
			break
		}

		switch req.Action {
		case "request_otp":
			if req.Email == "" {
				sendErrorToClient(conn, "Email is required")
				continue
			}

			var exists bool
			db.QueryRow("SELECT EXISTS(SELECT 1 FROM users WHERE email=$1)", req.Email).Scan(&exists)
			if exists {
				sendErrorToClient(conn, "Email already exists")
				continue
			}

			otp := fmt.Sprintf("%06d", rand.Intn(1000000))
			mutex.Lock()
			otpStorage[req.Email] = otp
			mutex.Unlock()

			go sendEmailOTP(req.Email, otp)
			sendJSON(conn, map[string]interface{}{"action": "otp_sent"})

		case "email_register":
			if req.Email == "" || req.Password == "" || req.Username == "" || req.OTP == "" {
				sendErrorToClient(conn, "Missing required fields")
				continue
			}

			mutex.Lock()
			savedOTP, exists := otpStorage[req.Email]
			mutex.Unlock()

			if !exists || savedOTP != req.OTP {
				sendErrorToClient(conn, "Invalid or expired OTP")
				continue
			}

			mutex.Lock()
			delete(otpStorage, req.Email)
			mutex.Unlock()

			hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
			if err != nil {
				sendErrorToClient(conn, "Error securing password")
				continue
			}

			var newUserID int
			err = db.QueryRow(
				"INSERT INTO users (email, username, password_hash) VALUES ($1, $2, $3) RETURNING id",
				req.Email, req.Username, string(hashedPassword),
			).Scan(&newUserID)

			if err != nil {
				sendErrorToClient(conn, "Username might be taken")
				continue
			}

			appToken, _ := generateJWT(newUserID, req.Email)
			sendJSON(conn, map[string]interface{}{
				"action":  "register_success",
				"jwt":     appToken,
				"user_id": newUserID,
			})
			fmt.Printf("✅ User %s Registered successfully!\n", req.Username)

		case "google_login":
			if req.Token == "" {
				continue
			}
			payload, err := idtoken.Validate(context.Background(), req.Token, googleClientID)
			if err != nil {
				continue
			}
			email := payload.Claims["email"].(string)
			name := payload.Claims["name"].(string)

			userID, err := getOrCreateUserByEmail(email, name)
			if err != nil {
				continue
			}

			appToken, err := generateJWT(userID, email)
			if err != nil {
				continue
			}

			mutex.Lock()
			userConnections[userID] = conn
			loggedInUserID = userID
			mutex.Unlock()

			sendJSON(conn, map[string]interface{}{
				"action":  "login_success",
				"jwt":     appToken,
				"user_id": userID,
			})

		case "register_connection":
			mutex.Lock()
			userConnections[req.UserID] = conn
			loggedInUserID = req.UserID
			mutex.Unlock()

		case "send_message":
			msgID, err := saveMessage(req.UserID, req.ReceiverID, req.Content, req.ImageURL)
			if err == nil {
				fullMsg, _ := getMessageByID(msgID)

				// 🟢 อัพเดตการส่งข้อมูลแบบใหม่
				responseMap := map[string]interface{}{"action": "new_message", "data": fullMsg}
				sendMessageToUser(req.ReceiverID, responseMap)
				sendMessageToUser(req.UserID, responseMap)
			}

		case "create_post":
			newPostID, err := createPost(req.UserID, req.Content, req.ImageURLs, nil)
			if err == nil {
				newPostData, _ := getSinglePost(newPostID)

				// 🟢 อัพเดตการ Boardcast แบบใหม่
				responseMap := map[string]interface{}{"action": "new_post", "data": newPostData}
				broadcast(responseMap)
			}
		}
	}
}

func sendEmailOTP(toEmail, otp string) error {
	from := os.Getenv("SMTP_EMAIL")
	password := os.Getenv("SMTP_PASSWORD")

	if from == "" || password == "" {
		return fmt.Errorf("SMTP credentials missing in environment variables")
	}

	smtpHost := "smtp.gmail.com"
	smtpPort := "587"

	msg := []byte("From: Tweety App\r\n" +
		"To: " + toEmail + "\r\n" +
		"Subject: Your Tweety Verification Code\r\n\r\n" +
		"Your verification code is: " + otp + "\r\n")

	auth := smtp.PlainAuth("", from, password, smtpHost)
	return smtp.SendMail(smtpHost+":"+smtpPort, auth, from, []string{toEmail}, msg)
}

// 🟢 Helper Function พื้นฐาน
func sendJSON(conn *websocket.Conn, data map[string]interface{}) {
	conn.WriteJSON(data)
}

func sendErrorToClient(conn *websocket.Conn, errMsg string) {
	sendJSON(conn, map[string]interface{}{"action": "error", "message": errMsg})
}

func generateJWT(userID int, email string) (string, error) {
	claims := jwt.MapClaims{"user_id": userID, "email": email, "exp": time.Now().Add(time.Hour * 24 * 7).Unix()}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(jwtSecretKey))
}

func getOrCreateUserByEmail(email string, username string) (int, error) {
	var userID int
	err := db.QueryRow("SELECT id FROM users WHERE email = $1", email).Scan(&userID)
	if err == sql.ErrNoRows {
		err = db.QueryRow("INSERT INTO users (email, username, password_hash) VALUES ($1, $2, $3) RETURNING id", email, username, "GOOGLE_OAUTH").Scan(&userID)
		return userID, err
	}
	return userID, err
}

// 🟢 อัพเดตฟังก์ชัน sendHistoryToClient (ใช้ *websocket.Conn)
func sendHistoryToClient(client *websocket.Conn) {
	posts, err := getFeedPosts()
	if err == nil {
		for i := len(posts) - 1; i >= 0; i-- {
			sendJSON(client, map[string]interface{}{"action": "new_post", "data": posts[i]})
		}
	}
}

// 🟢 อัพเดตฟังก์ชัน sendMessageToUser (รับ Data เป็น Map แล้วส่ง JSON ออกไป)
func sendMessageToUser(userID int, data map[string]interface{}) {
	mutex.Lock()
	defer mutex.Unlock()
	if conn, ok := userConnections[userID]; ok {
		conn.WriteJSON(data)
	}
}

// 🟢 อัพเดตฟังก์ชัน broadcast (รับ Data เป็น Map แล้วส่ง JSON ออกไป)
func broadcast(data map[string]interface{}) {
	mutex.Lock()
	defer mutex.Unlock()
	for _, conn := range userConnections {
		conn.WriteJSON(data)
	}
}

func createPost(userID int, content string, imageURLs []string, parentPostID *int) (int, error) {
	if imageURLs == nil {
		imageURLs = []string{}
	}
	var newPostID int
	err := db.QueryRow(`INSERT INTO posts (user_id, content, image_urls, parent_post_id) VALUES ($1, $2, $3, $4) RETURNING id`, userID, content, pq.Array(imageURLs), parentPostID).Scan(&newPostID)
	return newPostID, err
}

func getSinglePost(postID int) (*PostFeed, error) {
	var post PostFeed
	var imgURLs pq.StringArray
	err := db.QueryRow(`SELECT p.id, p.user_id, u.username, COALESCE(u.profile_image_url, ''), p.content, COALESCE(p.image_urls, '{}'), p.parent_post_id, (SELECT COUNT(*) FROM likes WHERE post_id = p.id) as like_count, p.created_at FROM posts p JOIN users u ON p.user_id = u.id WHERE p.id = $1`, postID).Scan(&post.PostID, &post.UserID, &post.Username, &post.ProfileImageURL, &post.Content, &imgURLs, &post.ParentPostID, &post.LikeCount, &post.CreatedAt)
	post.ImageURLs = []string(imgURLs)
	return &post, err
}

func getFeedPosts() ([]PostFeed, error) {
	rows, err := db.Query(`SELECT p.id, p.user_id, u.username, COALESCE(u.profile_image_url, ''), p.content, COALESCE(p.image_urls, '{}'), p.parent_post_id, (SELECT COUNT(*) FROM likes WHERE post_id = p.id) as like_count, p.created_at FROM posts p JOIN users u ON p.user_id = u.id WHERE p.parent_post_id IS NULL ORDER BY p.created_at DESC LIMIT 50`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var feed []PostFeed
	for rows.Next() {
		var post PostFeed
		var imgURLs pq.StringArray
		if err := rows.Scan(&post.PostID, &post.UserID, &post.Username, &post.ProfileImageURL, &post.Content, &imgURLs, &post.ParentPostID, &post.LikeCount, &post.CreatedAt); err == nil {
			post.ImageURLs = []string(imgURLs)
			feed = append(feed, post)
		}
	}
	return feed, nil
}

func saveMessage(senderID int, receiverID int, content string, imageURL string) (int, error) {
	var imgParam, contentParam interface{}
	if imageURL != "" {
		imgParam = imageURL
	}
	if content != "" {
		contentParam = content
	}
	var newMsgID int
	err := db.QueryRow(`INSERT INTO messages (sender_id, receiver_id, content, image_url) VALUES ($1, $2, $3, $4) RETURNING id`, senderID, receiverID, contentParam, imgParam).Scan(&newMsgID)
	return newMsgID, err
}

func getMessageByID(msgID int) (*Message, error) {
	var msg Message
	err := db.QueryRow(`SELECT id, sender_id, receiver_id, COALESCE(content, ''), image_url, is_read, created_at FROM messages WHERE id = $1`, msgID).Scan(&msg.ID, &msg.SenderID, &msg.ReceiverID, &msg.Content, &msg.ImageURL, &msg.IsRead, &msg.CreatedAt)
	return &msg, err
}
