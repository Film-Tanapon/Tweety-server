package main

import (
	"bufio"         // ใช้อ่านข้อมูลจากเครือข่ายทีละบรรทัด
	"context"       // จัดการเรื่องเวลา (Timeout), ยกเลิกคำสั่ง
	"database/sql"  // ติดต่อไป SQL
	"encoding/json" // json <-> struct
	"fmt"           // print text
	"log"           // บันทึก error
	"net"           // tcp
	"sync"          // ใช้ป้องกันไม่ให้พนักงาน (Thread) หลายคนแย่งกันแก้ไขข้อมูลเดียวกัน (Mutex)
	"time"          // ใช้จัดการเรื่องเวลา

	"github.com/golang-jwt/jwt/v5"
	"github.com/lib/pq"
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

// 🟢 โครงสร้างใหม่สำหรับระบบแชท
type Message struct {
	ID         int       `json:"id"`
	SenderID   int       `json:"sender_id"`
	ReceiverID int       `json:"receiver_id"`
	Content    string    `json:"content"`
	ImageURL   *string   `json:"image_url"` // ใช้ pointer เผื่อเป็น null
	IsRead     bool      `json:"is_read"`
	CreatedAt  time.Time `json:"created_at"`
}

type ActionRequest struct {
	Action     string   `json:"action"`
	UserID     int      `json:"user_id"`               // สำหรับ Post คือคนโพสต์, สำหรับ Message คือคนส่ง
	ReceiverID int      `json:"receiver_id,omitempty"` // 🟢 เพิ่ม: สำหรับ Message (คนรับ)
	PostID     int      `json:"post_id,omitempty"`
	Content    string   `json:"content,omitempty"`
	ImageURLs  []string `json:"image_urls,omitempty"` // สำหรับ Post
	ImageURL   string   `json:"image_url,omitempty"`  // 🟢 เพิ่ม: สำหรับ Message (ส่งได้ทีละรูป)
	Token      string   `json:"token,omitempty"`
}

// =====================================================================
// --- 2. Global Variables ---
// =====================================================================

var jwtSecretKey = []byte("Tweety_Super_Secret_Key_2026")
var googleClientID = "305844664566-7392po3uu4d377lvcqao4i9jcnj7plgc.apps.googleusercontent.com"

// 🟢 เปลี่ยนจากเก็บแค่ net.Conn เป็นเก็บ UserID คู่กับ net.Conn
// ทำให้เรารู้ว่าใคร (ID อะไร) กำลังใช้ Connection ไหนอยู่
var userConnections = make(map[int]net.Conn)
var mutex = &sync.Mutex{}
var db *sql.DB

// =====================================================================
// --- 3. Main Function ---
// =====================================================================

func main() {
	connStr := "postgresql://postgres.gapsfsqsefgvtgmncfky:TweetyProjectCN321@aws-1-ap-southeast-1.pooler.supabase.com:6543/postgres?sslmode=require"

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

	listener, err := net.Listen("tcp", "0.0.0.0:3000")
	if err != nil {
		fmt.Println("Error starting server:", err)
		return
	}
	defer listener.Close()
	fmt.Println("🚀 Server Started on port 3000...")

	for {
		conn, err := listener.Accept()
		if err != nil {
			fmt.Println("Error accepting:", err)
			continue
		}

		fmt.Println("New client connected:", conn.RemoteAddr())
		// สังเกตว่าเรายังไม่เอาเข้า userConnections ทันที
		// รอให้ Client ส่ง action "register_connection" มาบอก UserID ก่อน
		go handleClient(conn)
	}
}

// =====================================================================
// --- 4. Client Handler ---
// =====================================================================

func handleClient(conn net.Conn) {
	var loggedInUserID int // ตัวแปรจำว่า Connection นี้คือของ UserID อะไร

	defer func() {
		conn.Close()
		// ลบออกจากระบบเมื่อ Client ตัดการเชื่อมต่อ
		if loggedInUserID != 0 {
			mutex.Lock()
			delete(userConnections, loggedInUserID)
			mutex.Unlock()
			fmt.Printf("User %d disconnected\n", loggedInUserID)
		}
	}()

	// ส่งประวัติ Post Feed ทันทีที่เชื่อมต่อ (ฟังก์ชันเดิม ไม่กระทบ)
	sendHistoryToClient(conn)

	reader := bufio.NewReader(conn)
	for {
		messageLine, err := reader.ReadString('\n')
		if err != nil {
			return // ออกจากลูปเมื่อเกิด Error หรือตัดการเชื่อมต่อ
		}

		fmt.Printf("Received: %s", messageLine)

		var req ActionRequest
		err = json.Unmarshal([]byte(messageLine), &req)

		if err == nil {
			switch req.Action {

			case "google_login":
				if req.Token == "" {
					fmt.Println("❌ Missing token")
					continue
				}

				// ก. ยืนยัน Token กับ Google
				payload, err := idtoken.Validate(context.Background(), req.Token, googleClientID)
				if err != nil {
					fmt.Println("❌ Invalid Google Token:", err)
					continue
				}

				// ข. ดึงข้อมูลอีเมลและชื่อออกมา
				email := payload.Claims["email"].(string)
				name := payload.Claims["name"].(string)
				// picture := payload.Claims["picture"].(string) // ถ้าอยากดึงรูปโปรไฟล์

				// ค. หาใน Database ว่ามี User นี้หรือยัง (ถ้าไม่มีให้สร้างใหม่)
				userID, err := getOrCreateUserByEmail(email, name)
				if err != nil {
					fmt.Println("❌ Error DB getOrCreateUser:", err)
					continue
				}

				// ง. สร้าง JWT (App Token) ของระบบเรา
				appToken, err := generateJWT(userID, email)
				if err != nil {
					fmt.Println("❌ Error generating JWT:", err)
					continue
				}

				// จ. จับ Connection นี้ผูกกับ UserID ทันที (ล็อกอินสำเร็จ)
				mutex.Lock()
				userConnections[userID] = conn
				loggedInUserID = userID
				mutex.Unlock()

				// ฉ. ส่ง JWT กลับไปให้ Flutter
				response := map[string]interface{}{
					"action":  "login_success",
					"jwt":     appToken,
					"user_id": userID,
				}
				jsonResp, _ := json.Marshal(response)
				conn.Write(append(jsonResp, '\n'))
				fmt.Printf("✅ Google Login Success! Issued JWT for User %d\n", userID)

			// 🟢 1. การลงทะเบียน Connection เข้ากับ UserID
			case "register_connection":
				mutex.Lock()
				userConnections[req.UserID] = conn
				loggedInUserID = req.UserID
				mutex.Unlock()
				fmt.Printf("✅ User %d registered their connection\n", req.UserID)

			// 🟢 2. การส่งข้อความส่วนตัว (Direct Message)
			case "send_message":
				if req.ReceiverID == 0 {
					fmt.Println("❌ Error: Missing receiver_id")
					continue
				}

				// บันทึกลง Database
				msgID, err := saveMessage(req.UserID, req.ReceiverID, req.Content, req.ImageURL)
				if err == nil {
					// ดึงข้อมูลเต็มกลับมา (พร้อม Timestamp)
					fullMsg, err := getMessageByID(msgID)
					if err == nil {
						// ห่อข้อมูลเพื่อบอก Client ว่านี่คือ Message นะ ไม่ใช่ Post Feed
						responseMap := map[string]interface{}{
							"action": "new_message",
							"data":   fullMsg,
						}
						msgJSON, _ := json.Marshal(responseMap)

						// ส่งไปหาคนรับ (ถ้าออนไลน์)
						sendMessageToUser(req.ReceiverID, append(msgJSON, '\n'))
						// ส่งกลับไปหาตัวเองด้วย (เผื่อใช้อัปเดต UI ทันที)
						sendMessageToUser(req.UserID, append(msgJSON, '\n'))
					}
				}

			// 🟡 3. ฟังก์ชันเดิม (Post Feed)
			case "create_post":
				newPostID, err := createPost(req.UserID, req.Content, req.ImageURLs, nil)
				if err == nil {
					newPostData, err := getSinglePost(newPostID)
					if err == nil {
						// ห่อข้อมูลเพื่อให้ Client แยกแยะได้ (Optionally) หรือส่งตรงๆ แบบเดิม
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

func generateJWT(userID int, email string) (string, error) {
	// กำหนดข้อมูลที่จะใส่ลงในบัตร (Claims)
	claims := jwt.MapClaims{
		"user_id": userID,
		"email":   email,
		"exp":     time.Now().Add(time.Hour * 24 * 7).Unix(), // หมดอายุใน 7 วัน
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(jwtSecretKey)
}

func getOrCreateUserByEmail(email string, username string) (int, error) {
	var userID int
	// ลองหาจาก DB
	err := db.QueryRow("SELECT id FROM users WHERE email = $1", email).Scan(&userID)

	if err == sql.ErrNoRows {
		// ถ้าไม่เจอ (คนเพิ่งเคยเข้าครั้งแรก) ให้ Insert
		err = db.QueryRow(
			"INSERT INTO users (email, username) VALUES ($1, $2) RETURNING id",
			email, username,
		).Scan(&userID)
		if err != nil {
			return 0, err
		}
		fmt.Println("✨ Created new user from Google:", email)
		return userID, nil
	} else if err != nil {
		return 0, err
	}

	return userID, nil // เจอใน DB คืนค่า ID เดิมกลับไป
}

// =====================================================================
// --- 5. Network Functions ---
// =====================================================================

func sendHistoryToClient(client net.Conn) {
	posts, err := getFeedPosts()
	if err != nil {
		fmt.Println("❌ Error querying feed history:", err)
		return
	}

	for i := len(posts) - 1; i >= 0; i-- {
		p := posts[i]

		// ห่อข้อมูลเพื่อให้ Client รู้ว่าเป็นชนิด new_post (ปรับให้เข้ากับ Message)
		responseMap := map[string]interface{}{
			"action": "new_post",
			"data":   p,
		}
		jsonData, _ := json.Marshal(responseMap)
		client.Write(append(jsonData, '\n'))
	}
	fmt.Println("✅ Sent feed history to client")
}

// 🟢 ส่งข้อมูลให้เฉพาะคนๆ เดียว (เช่น DM)
func sendMessageToUser(userID int, data []byte) {
	mutex.Lock()
	defer mutex.Unlock()

	if conn, ok := userConnections[userID]; ok {
		_, err := conn.Write(data)
		if err != nil {
			fmt.Printf("Error sending to user %d: %v\n", userID, err)
			conn.Close()
			delete(userConnections, userID)
		}
	} else {
		// ถ้าไม่ได้ออนไลน์อยู่ ข้อความก็ถูกเซฟลง DB ไปแล้ว ไม่เป็นไร
		fmt.Printf("User %d is offline.\n", userID)
	}
}

// ส่งให้ทุกคนที่อยู่ในระบบ (เช่น New Feed)
func broadcast(data []byte) {
	mutex.Lock()
	defer mutex.Unlock()

	for userID, conn := range userConnections {
		_, err := conn.Write(data)
		if err != nil {
			fmt.Printf("Error broadcasting to user %d: %v\n", userID, err)
			conn.Close()
			delete(userConnections, userID)
		}
	}
}

// =====================================================================
// --- 6. Database Functions (Post / Feed) ---
// =====================================================================

func createPost(userID int, content string, imageURLs []string, parentPostID *int) (int, error) {
	if imageURLs == nil {
		imageURLs = []string{}
	}

	sqlStatement := `
        INSERT INTO posts (user_id, content, image_urls, parent_post_id) 
        VALUES ($1, $2, $3, $4)
        RETURNING id
    `
	var newPostID int
	err := db.QueryRow(sqlStatement, userID, content, pq.Array(imageURLs), parentPostID).Scan(&newPostID)

	if err != nil {
		fmt.Println("❌ Error creating post:", err)
		return 0, err
	}
	fmt.Println("✅ Post created successfully! ID:", newPostID)
	return newPostID, nil
}

func getSinglePost(postID int) (*PostFeed, error) {
	sqlStatement := `
        SELECT 
            p.id, p.user_id, u.username, COALESCE(u.profile_image_url, ''), 
            p.content, COALESCE(p.image_urls, '{}'), p.parent_post_id,
            (SELECT COUNT(*) FROM likes WHERE post_id = p.id) as like_count,
            p.created_at
        FROM posts p
        JOIN users u ON p.user_id = u.id
        WHERE p.id = $1
    `
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
        SELECT 
            p.id, p.user_id, u.username, COALESCE(u.profile_image_url, ''), 
            p.content, COALESCE(p.image_urls, '{}'), p.parent_post_id,
            (SELECT COUNT(*) FROM likes WHERE post_id = p.id) as like_count,
            p.created_at
        FROM posts p
        JOIN users u ON p.user_id = u.id
        WHERE p.parent_post_id IS NULL 
        ORDER BY p.created_at DESC
        LIMIT 50;
    `
	rows, err := db.Query(sqlStatement)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var feed []PostFeed
	for rows.Next() {
		var post PostFeed
		var imgURLs pq.StringArray

		err := rows.Scan(
			&post.PostID, &post.UserID, &post.Username, &post.ProfileImageURL,
			&post.Content, &imgURLs, &post.ParentPostID, &post.LikeCount, &post.CreatedAt,
		)
		if err == nil {
			post.ImageURLs = []string(imgURLs)
			feed = append(feed, post)
		} else {
			fmt.Println("Scan Error:", err)
		}
	}
	return feed, nil
}

// =====================================================================
// --- 7. Database Functions (Messages) --- 🟢 (เพิ่มใหม่)
// =====================================================================

func saveMessage(senderID int, receiverID int, content string, imageURL string) (int, error) {
	var imgParam interface{} = imageURL
	if imageURL == "" {
		imgParam = nil
	}

	var contentParam interface{} = content
	if content == "" {
		contentParam = nil
	}

	sqlStatement := `
        INSERT INTO messages (sender_id, receiver_id, content, image_url) 
        VALUES ($1, $2, $3, $4)
        RETURNING id
    `
	var newMsgID int
	err := db.QueryRow(sqlStatement, senderID, receiverID, contentParam, imgParam).Scan(&newMsgID)

	if err != nil {
		fmt.Println("❌ Error saving message:", err)
		return 0, err
	}
	fmt.Println("📩 Message saved! ID:", newMsgID)
	return newMsgID, nil
}

func getMessageByID(msgID int) (*Message, error) {
	sqlStatement := `
        SELECT id, sender_id, receiver_id, COALESCE(content, ''), image_url, is_read, created_at 
        FROM messages WHERE id = $1
    `
	var msg Message
	err := db.QueryRow(sqlStatement, msgID).Scan(
		&msg.ID, &msg.SenderID, &msg.ReceiverID,
		&msg.Content, &msg.ImageURL, &msg.IsRead, &msg.CreatedAt,
	)

	if err != nil {
		return nil, err
	}
	return &msg, nil
}

// =====================================================================
// --- 8. Interaction Functions ---
// =====================================================================

func toggleLike(userID int, postID int) {
	var exists bool
	db.QueryRow(`SELECT EXISTS(SELECT 1 FROM likes WHERE user_id = $1 AND post_id = $2)`, userID, postID).Scan(&exists)

	if exists {
		db.Exec(`DELETE FROM likes WHERE user_id = $1 AND post_id = $2`, userID, postID)
		fmt.Println("💔 Unliked post")
	} else {
		db.Exec(`INSERT INTO likes (user_id, post_id) VALUES ($1, $2)`, userID, postID)
		fmt.Println("❤️ Liked post")
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
