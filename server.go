package main

import (
	"bufio"         // ใช้อ่านข้อมูลจากเครือข่ายทีละบรรทัด
	"context"       // จัดการเรื่องเวลา (Timeout), ยกเลิกคำสั่ง
	"database/sql"  // ติดต่อไป SQL
	"encoding/json" // json <-> struct
	"fmt"           // print text
	"log"           // บันทึก error
	"net"           // tcp
	"os"
	"sync" // ใช้ป้องกันไม่ให้พนักงาน (Thread) หลายคนแย่งกันแก้ไขข้อมูลเดียวกัน (Mutex)
	"time" // ใช้จัดการเรื่องเวลา

	"github.com/golang-jwt/jwt/v5"
	"github.com/lib/pq"
	"golang.org/x/crypto/bcrypt" // 🟢 เพิ่มไลบรารีสำหรับเข้ารหัส Password
	"google.golang.org/api/idtoken"
)

// =====================================================================
// --- 1. Structs ---
// =====================================================================

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
	// 🟢 เพิ่มฟิลด์สำหรับการสมัครสมาชิกด้วย Email/Password
	Email    string `json:"email,omitempty"`
	Username string `json:"username,omitempty"`
	Password string `json:"password,omitempty"`
}

// =====================================================================
// --- 2. Global Variables ---
// =====================================================================

var jwtSecretKey = os.Getenv("JWT_SECRET")
var googleClientID = os.Getenv("GOOGLE_CLIENT_ID")

var userConnections = make(map[int]net.Conn)
var mutex = &sync.Mutex{}
var db *sql.DB

// =====================================================================
// --- 3. Main Function ---
// =====================================================================

func main() {
	connStr := os.Getenv("DB_URL")

	var err error
	db, err = sql.Open("postgres", connStr)
	if err != nil {
		log.Fatal("Error opening database:", err)
	}
	defer db.Close()

	err = db.Ping()
	if err != nil {
		log.Fatal("Cannot connect to Supabase:", err)
	}
	fmt.Println("✅ Connected to Supabase successfully!")

	port := os.Getenv("PORT")
	if port == "" {
		port = "3000"
	}

	listener, err := net.Listen("tcp", "0.0.0.0:"+port)
	if err != nil {
		fmt.Println("Error starting server:", err)
		return
	}
	defer listener.Close()
	fmt.Println("🚀 Server Started on port", port, "...")

	for {
		conn, err := listener.Accept()
		if err != nil {
			fmt.Println("Error accepting:", err)
			continue
		}

		fmt.Println("New client connected:", conn.RemoteAddr())
		go handleClient(conn)
	}
}

// =====================================================================
// --- 4. Client Handler ---
// =====================================================================

func handleClient(conn net.Conn) {
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

	reader := bufio.NewReader(conn)
	for {
		messageLine, err := reader.ReadString('\n')
		if err != nil {
			return
		}

		fmt.Printf("Received: %s", messageLine)

		var req ActionRequest
		err = json.Unmarshal([]byte(messageLine), &req)

		if err == nil {
			switch req.Action {

			// 🟢 Action สมัครสมาชิกจาก Flutter
			case "email_register":
				if req.Email == "" || req.Password == "" || req.Username == "" {
					sendErrorToClient(conn, "Missing required fields")
					continue
				}

				// เข้ารหัส Password
				hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
				if err != nil {
					sendErrorToClient(conn, "Error hashing password")
					continue
				}

				// บันทึกลง Database
				var newUserID int
				err = db.QueryRow(
					"INSERT INTO users (email, username, password_hash) VALUES ($1, $2, $3) RETURNING id",
					req.Email, req.Username, string(hashedPassword),
				).Scan(&newUserID)

				if err != nil {
					sendErrorToClient(conn, "Email or Username already exists")
					continue
				}

				// สร้าง JWT ให้หลังจากสมัครเสร็จ
				appToken, _ := generateJWT(newUserID, req.Email)

				response := map[string]interface{}{
					"action":  "register_success",
					"jwt":     appToken,
					"user_id": newUserID,
				}
				jsonResp, _ := json.Marshal(response)
				conn.Write(append(jsonResp, '\n'))
				fmt.Printf("✅ User %s Registered successfully! ID: %d\n", req.Username, newUserID)

			case "google_login":
				if req.Token == "" {
					fmt.Println("❌ Missing token")
					continue
				}

				payload, err := idtoken.Validate(context.Background(), req.Token, googleClientID)
				if err != nil {
					fmt.Println("❌ Invalid Google Token:", err)
					continue
				}

				email := payload.Claims["email"].(string)
				name := payload.Claims["name"].(string)

				userID, err := getOrCreateUserByEmail(email, name)
				if err != nil {
					fmt.Println("❌ Error DB getOrCreateUser:", err)
					continue
				}

				appToken, err := generateJWT(userID, email)
				if err != nil {
					fmt.Println("❌ Error generating JWT:", err)
					continue
				}

				mutex.Lock()
				userConnections[userID] = conn
				loggedInUserID = userID
				mutex.Unlock()

				response := map[string]interface{}{
					"action":  "login_success",
					"jwt":     appToken,
					"user_id": userID,
				}
				jsonResp, _ := json.Marshal(response)
				conn.Write(append(jsonResp, '\n'))
				fmt.Printf("✅ Google Login Success! Issued JWT for User %d\n", userID)

			case "register_connection":
				mutex.Lock()
				userConnections[req.UserID] = conn
				loggedInUserID = req.UserID
				mutex.Unlock()
				fmt.Printf("✅ User %d registered their connection\n", req.UserID)

			case "send_message":
				if req.ReceiverID == 0 {
					fmt.Println("❌ Error: Missing receiver_id")
					continue
				}

				msgID, err := saveMessage(req.UserID, req.ReceiverID, req.Content, req.ImageURL)
				if err == nil {
					fullMsg, err := getMessageByID(msgID)
					if err == nil {
						responseMap := map[string]interface{}{
							"action": "new_message",
							"data":   fullMsg,
						}
						msgJSON, _ := json.Marshal(responseMap)

						sendMessageToUser(req.ReceiverID, append(msgJSON, '\n'))
						sendMessageToUser(req.UserID, append(msgJSON, '\n'))
					}
				}

			case "create_post":
				newPostID, err := createPost(req.UserID, req.Content, req.ImageURLs, nil)
				if err == nil {
					newPostData, err := getSinglePost(newPostID)
					if err == nil {
						responseMap := map[string]interface{}{
							"action": "new_post",
							"data":   newPostData,
						}
						postJSON, _ := json.Marshal(responseMap)
						broadcast(append(postJSON, '\n'))
					}
				}

			case "toggle_like":
				toggleLike(req.UserID, req.PostID)

			case "toggle_repost":
				toggleRepost(req.UserID, req.PostID)

			case "toggle_bookmark":
				toggleBookmark(req.UserID, req.PostID)
			}
		} else {
			fmt.Println("JSON Parse Error:", err)
		}
	}
}

// 🟢 ฟังก์ชันส่ง Error กลับไปหา Flutter
func sendErrorToClient(conn net.Conn, errMsg string) {
	response := map[string]interface{}{
		"action":  "error",
		"message": errMsg,
	}
	jsonResp, _ := json.Marshal(response)
	conn.Write(append(jsonResp, '\n'))
}

func generateJWT(userID int, email string) (string, error) {
	claims := jwt.MapClaims{
		"user_id": userID,
		"email":   email,
		"exp":     time.Now().Add(time.Hour * 24 * 7).Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(jwtSecretKey)) // แก้ไขให้รับ []byte
}

func getOrCreateUserByEmail(email string, username string) (int, error) {
	var userID int
	err := db.QueryRow("SELECT id FROM users WHERE email = $1", email).Scan(&userID)

	if err == sql.ErrNoRows {
		// 🟢 แก้ไข: Database ระบุว่า password_hash NOT NULL จึงต้องใส่ String ว่างไว้สำหรับ Google User
		err = db.QueryRow(
			"INSERT INTO users (email, username, password_hash) VALUES ($1, $2, $3) RETURNING id",
			email, username, "GOOGLE_OAUTH",
		).Scan(&userID)
		if err != nil {
			return 0, err
		}
		fmt.Println("✨ Created new user from Google:", email)
		return userID, nil
	} else if err != nil {
		return 0, err
	}

	return userID, nil
}

// =====================================================================
// --- 5. Network & Database Functions (คงเดิม) ---
// =====================================================================

func sendHistoryToClient(client net.Conn) {
	posts, err := getFeedPosts()
	if err != nil {
		return
	}
	for i := len(posts) - 1; i >= 0; i-- {
		p := posts[i]
		responseMap := map[string]interface{}{
			"action": "new_post",
			"data":   p,
		}
		jsonData, _ := json.Marshal(responseMap)
		client.Write(append(jsonData, '\n'))
	}
}

func sendMessageToUser(userID int, data []byte) {
	mutex.Lock()
	defer mutex.Unlock()

	if conn, ok := userConnections[userID]; ok {
		_, err := conn.Write(data)
		if err != nil {
			conn.Close()
			delete(userConnections, userID)
		}
	}
}

func broadcast(data []byte) {
	mutex.Lock()
	defer mutex.Unlock()

	for userID, conn := range userConnections {
		_, err := conn.Write(data)
		if err != nil {
			conn.Close()
			delete(userConnections, userID)
		}
	}
}

func createPost(userID int, content string, imageURLs []string, parentPostID *int) (int, error) {
	if imageURLs == nil {
		imageURLs = []string{}
	}
	sqlStatement := `INSERT INTO posts (user_id, content, image_urls, parent_post_id) VALUES ($1, $2, $3, $4) RETURNING id`
	var newPostID int
	err := db.QueryRow(sqlStatement, userID, content, pq.Array(imageURLs), parentPostID).Scan(&newPostID)
	return newPostID, err
}

func getSinglePost(postID int) (*PostFeed, error) {
	sqlStatement := `
		SELECT p.id, p.user_id, u.username, COALESCE(u.profile_image_url, ''), p.content, COALESCE(p.image_urls, '{}'), p.parent_post_id,
		(SELECT COUNT(*) FROM likes WHERE post_id = p.id) as like_count, p.created_at
		FROM posts p JOIN users u ON p.user_id = u.id WHERE p.id = $1`
	var post PostFeed
	var imgURLs pq.StringArray
	err := db.QueryRow(sqlStatement, postID).Scan(
		&post.PostID, &post.UserID, &post.Username, &post.ProfileImageURL,
		&post.Content, &imgURLs, &post.ParentPostID, &post.LikeCount, &post.CreatedAt,
	)
	if err != nil {
		return nil, err
	}
	post.ImageURLs = []string(imgURLs)
	return &post, nil
}

func getFeedPosts() ([]PostFeed, error) {
	sqlStatement := `
		SELECT p.id, p.user_id, u.username, COALESCE(u.profile_image_url, ''), p.content, COALESCE(p.image_urls, '{}'), p.parent_post_id,
		(SELECT COUNT(*) FROM likes WHERE post_id = p.id) as like_count, p.created_at
		FROM posts p JOIN users u ON p.user_id = u.id WHERE p.parent_post_id IS NULL ORDER BY p.created_at DESC LIMIT 50;`
	rows, err := db.Query(sqlStatement)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var feed []PostFeed
	for rows.Next() {
		var post PostFeed
		var imgURLs pq.StringArray
		if err := rows.Scan(
			&post.PostID, &post.UserID, &post.Username, &post.ProfileImageURL,
			&post.Content, &imgURLs, &post.ParentPostID, &post.LikeCount, &post.CreatedAt,
		); err == nil {
			post.ImageURLs = []string(imgURLs)
			feed = append(feed, post)
		}
	}
	return feed, nil
}

func saveMessage(senderID int, receiverID int, content string, imageURL string) (int, error) {
	var imgParam interface{} = imageURL
	if imageURL == "" {
		imgParam = nil
	}
	var contentParam interface{} = content
	if content == "" {
		contentParam = nil
	}
	sqlStatement := `INSERT INTO messages (sender_id, receiver_id, content, image_url) VALUES ($1, $2, $3, $4) RETURNING id`
	var newMsgID int
	err := db.QueryRow(sqlStatement, senderID, receiverID, contentParam, imgParam).Scan(&newMsgID)
	return newMsgID, err
}

func getMessageByID(msgID int) (*Message, error) {
	sqlStatement := `SELECT id, sender_id, receiver_id, COALESCE(content, ''), image_url, is_read, created_at FROM messages WHERE id = $1`
	var msg Message
	err := db.QueryRow(sqlStatement, msgID).Scan(
		&msg.ID, &msg.SenderID, &msg.ReceiverID, &msg.Content, &msg.ImageURL, &msg.IsRead, &msg.CreatedAt,
	)
	return &msg, err
}

func toggleLike(userID int, postID int) {
	var exists bool
	db.QueryRow(`SELECT EXISTS(SELECT 1 FROM likes WHERE user_id = $1 AND post_id = $2)`, userID, postID).Scan(&exists)
	if exists {
		db.Exec(`DELETE FROM likes WHERE user_id = $1 AND post_id = $2`, userID, postID)
	} else {
		db.Exec(`INSERT INTO likes (user_id, post_id) VALUES ($1, $2)`, userID, postID)
	}
}

func toggleRepost(userID int, postID int) {
	var exists bool
	db.QueryRow(`SELECT EXISTS(SELECT 1 FROM reposts WHERE user_id = $1 AND post_id = $2)`, userID, postID).Scan(&exists)
	if exists {
		db.Exec(`DELETE FROM reposts WHERE user_id = $1 AND post_id = $2`, userID, postID)
	} else {
		db.Exec(`INSERT INTO reposts (user_id, post_id) VALUES ($1, $2)`, userID, postID)
	}
}

func toggleBookmark(userID int, postID int) {
	var exists bool
	db.QueryRow(`SELECT EXISTS(SELECT 1 FROM bookmarks WHERE user_id = $1 AND post_id = $2)`, userID, postID).Scan(&exists)
	if exists {
		db.Exec(`DELETE FROM bookmarks WHERE user_id = $1 AND post_id = $2`, userID, postID)
	} else {
		db.Exec(`INSERT INTO bookmarks (user_id, post_id) VALUES ($1, $2)`, userID, postID)
	}
}
