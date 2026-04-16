package main

import (
	"context"
	"fmt"
	"net/http"
	"sync"

	"cloud.google.com/go/auth/credentials/idtoken"
	"github.com/gorilla/websocket"
	"golang.org/x/crypto/bcrypt"
)

var userConnections = make(map[int]*websocket.Conn)
var mutex = &sync.Mutex{}

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool {
		return true
	},
}

// Helper Functions
func sendJSON(conn *websocket.Conn, data map[string]interface{}) {
	conn.WriteJSON(data)
}

func sendErrorToClient(conn *websocket.Conn, errMsg string) {
	sendJSON(conn, map[string]interface{}{"action": "error", "message": errMsg})
}

// ======================================================================LOGIN========================================================================//
func handleEmailRegister(conn *websocket.Conn, req ActionRequest) {
	if req.Email == "" || req.Password == "" || req.Username == "" {
		sendErrorToClient(conn, "Missing required fields")
		return
	}

	var username_exists bool
	db.QueryRow("SELECT EXISTS(SELECT 1 FROM users WHERE username=$1)", req.Username).Scan(&username_exists)
	if username_exists {
		sendErrorToClient(conn, "Username already exists")
		return
	}

	var email_exists bool
	db.QueryRow("SELECT EXISTS(SELECT 1 FROM users WHERE email=$1)", req.Email).Scan(&email_exists)
	if email_exists {
		sendErrorToClient(conn, "Email already exists")
		return
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		sendErrorToClient(conn, "Error securing password")
		return
	}

	var newUserID int
	err = db.QueryRow(
		"INSERT INTO users (email, username, password_hash) VALUES ($1, $2, $3) RETURNING id",
		req.Email, req.Username, string(hashedPassword),
	).Scan(&newUserID)

	if err != nil {
		sendErrorToClient(conn, "Username might be taken")
		return
	}
	fmt.Printf("✅ User %s Registered successfully!\n", req.Username)

	sendJSON(conn, map[string]interface{}{
		"action":  "register_success",
		"message": "สมัครสมาชิกสำเร็จแล้ว!",
	})
}

func handleLogin(conn *websocket.Conn, req ActionRequest, loggedInUserID *int) {
	if req.Username == "" || req.Password == "" {
		sendErrorToClient(conn, "กรุณากรอกข้อมูลให้ครบ")
		return
	}

	var userID int
	var passwordHash, email, dbUsername string

	query := `SELECT id, email, password_hash, username FROM users WHERE email = $1 OR username = $1`
	err := db.QueryRow(query, req.Username).Scan(&userID, &email, &passwordHash, &dbUsername)
	if err != nil || bcrypt.CompareHashAndPassword([]byte(passwordHash), []byte(req.Password)) != nil {
		sendErrorToClient(conn, "ชื่อผู้ใช้ อีเมล หรือ รหัสผ่านไม่ถูกต้อง")
		return
	}

	appToken, _ := generateJWT(userID, email)

	// บันทึกว่าผู้ใช้นี้เชื่อมต่อเข้ามาแล้ว
	mutex.Lock()
	userConnections[userID] = conn
	*loggedInUserID = userID
	mutex.Unlock()

	sendJSON(conn, map[string]interface{}{
		"jwt":      appToken,
		"user_id":  userID,
		"username": dbUsername,
	})
	fmt.Printf("✅ User %s Logged in successfully!\n", req.Username)
}

func handleGoogleLogin(conn *websocket.Conn, req ActionRequest, loggedInUserID *int) {
	if req.Token == "" {
		sendErrorToClient(conn, "Token is empty")
		return
	}

	payload, err := idtoken.Validate(context.Background(), req.Token, googleClientID)
	if err != nil {
		sendErrorToClient(conn, "Invalid Google Token")
		return
	}

	email := payload.Claims["email"].(string)
	name := payload.Claims["name"].(string)

	userID, err := getOrCreateUserByEmail(email, name)
	if err != nil {
		sendErrorToClient(conn, "Error verifying user")
		return
	}

	appToken, err := generateJWT(userID, email)
	if err != nil {
		sendErrorToClient(conn, "Error generating token")
		return
	}

	mutex.Lock()
	userConnections[userID] = conn
	*loggedInUserID = userID
	mutex.Unlock()

	sendJSON(conn, map[string]interface{}{
		"jwt":      appToken,
		"user_id":  userID,
		"username": name,
	})
}

// ======================================================================POST========================================================================//
func sendHistoryToClient(conn *websocket.Conn, userID int) {
	posts, err := getFeedPostsWithUser(userID)
	if err != nil {
		fmt.Println("Error loading posts:", err)
		return
	}

	sendJSON(conn, map[string]interface{}{
		"action": "post_history",
		"data":   posts,
	})
}

func handleCreatePost(req ActionRequest) {
	if req.UserID == 0 {
		return
	}

	newPostID, err := createPost(req.UserID, req.Content, req.ImageURLs, nil)
	if err == nil {
		newPostData, _ := getSinglePost(newPostID)
		responseMap := map[string]interface{}{"action": "new_post", "data": newPostData}

		// Broadcast ให้ทุกคนเห็นโพสต์ใหม่ในฟีด
		broadcast(responseMap)
	}
}

func handleDeletePost(conn *websocket.Conn, req ActionRequest) {
	if req.UserID == 0 || req.PostID == 0 {
		sendErrorToClient(conn, "Missing UserID or PostID")
		return
	}

	err := deletePost(req.PostID, req.UserID)
	if err != nil {
		sendErrorToClient(conn, "ไม่สามารถลบโพสต์ได้ หรือคุณไม่ใช่เจ้าของโพสต์")
		return
	}

	// แจ้งทุกคนให้ดึงโพสต์นี้ออกจากหน้าฟีด
	broadcast(map[string]interface{}{
		"action":  "post_deleted",
		"post_id": req.PostID,
	})
}

func handleLike(conn *websocket.Conn, req ActionRequest, loggedInUserID int) {
	if loggedInUserID == 0 {
		sendErrorToClient(conn, "Please login first")
		return
	}

	postID := req.PostID

	status, err := toggleLike(loggedInUserID, postID)
	if err != nil {
		sendErrorToClient(conn, "Failed to toggle like")
		return
	}

	fmt.Printf("User %d toggled like for post %d. New status: %v\n", loggedInUserID, postID, status)
}

func handleRepost(conn *websocket.Conn, req ActionRequest, loggedInUserID int) {
	if loggedInUserID == 0 {
		sendErrorToClient(conn, "Please login first")
		return
	}

	postID := req.PostID

	status, err := toggleRepost(loggedInUserID, postID)
	if err != nil {
		sendErrorToClient(conn, "Failed to toggle repost")
		return
	}

	fmt.Printf("User %d toggled repost for post %d. New status: %v\n", loggedInUserID, postID, status)
}

func handleBookmark(conn *websocket.Conn, req ActionRequest, loggedInUserID int) {
	if loggedInUserID == 0 {
		sendErrorToClient(conn, "Please login first")
		return
	}

	postID := req.PostID

	status, err := toggleBookmark(loggedInUserID, postID)
	if err != nil {
		sendErrorToClient(conn, "Failed to toggle bookmark")
		return
	}

	fmt.Printf("User %d toggled bookmark for post %d. New status: %v\n", loggedInUserID, postID, status)
}

// ======================================================================USER========================================================================//
func handleUpdateProfile(conn *websocket.Conn, req ActionRequest) {
	if req.UserID == 0 {
		sendErrorToClient(conn, "Unauthorized")
		return
	}

	err := updateUserProfile(req.UserID, req.Username, req.ImageURL, req.ImageURLs[0])
	if err != nil {
		sendErrorToClient(conn, "Failed to update profile")
		return
	}

	sendJSON(conn, map[string]interface{}{
		"action":  "profile_updated",
		"message": "อัปเดตโปรไฟล์สำเร็จ",
	})
}

// ======================================================================MESSAGE========================================================================//
func sendMessageToUser(userID int, data map[string]interface{}) {
	mutex.Lock()
	defer mutex.Unlock()
	if conn, ok := userConnections[userID]; ok {
		conn.WriteJSON(data)
	}
}

func handleGetChatHistory(conn *websocket.Conn, req ActionRequest) {
	if req.UserID == 0 || req.ReceiverID == 0 {
		sendErrorToClient(conn, "Missing UserID or ReceiverID")
		return
	}

	history, err := getChatHistory(req.UserID, req.ReceiverID)
	if err != nil {
		sendErrorToClient(conn, "Failed to load chat history")
		return
	}

	sendJSON(conn, map[string]interface{}{
		"action": "load_chat_history",
		"data":   history,
	})
}

func handleSendMessage(req ActionRequest) {
	if req.UserID == 0 || req.ReceiverID == 0 {
		return
	}

	msgID, err := saveMessage(req.UserID, req.ReceiverID, req.Content, req.ImageURL)
	if err == nil {
		fullMsg, _ := getMessageByID(msgID)
		responseMap := map[string]interface{}{"action": "new_message", "data": fullMsg}

		// ส่งกลับไปให้ทั้งผู้รับและผู้ส่ง เพื่อให้อัปเดต UI หน้าแชทได้เรียลไทม์
		sendMessageToUser(req.ReceiverID, responseMap)
		sendMessageToUser(req.UserID, responseMap)
	}
}

func handleDeleteMessage(conn *websocket.Conn, req ActionRequest) {
	// ต้องมี Message ID ส่งมาด้วย สมมติว่าอยู่ในฟิลด์ PostID หรือสร้างฟิลด์ MessageID ใหม่ใน ActionRequest
	msgID := req.PostID

	if req.UserID == 0 || msgID == 0 {
		sendErrorToClient(conn, "Invalid request")
		return
	}

	err := deleteMessage(msgID, req.UserID)
	if err != nil {
		sendErrorToClient(conn, "ไม่สามารถยกเลิกข้อความได้")
		return
	}

	// แจ้งเตือนไปยังฝั่งรับเพื่อให้ลบข้อความออกจากหน้าจอ
	if req.ReceiverID != 0 {
		sendMessageToUser(req.ReceiverID, map[string]interface{}{
			"action":     "message_deleted",
			"message_id": msgID,
		})
	}
}

func broadcast(data map[string]interface{}) {
	mutex.Lock()
	defer mutex.Unlock()
	for _, conn := range userConnections {
		conn.WriteJSON(data)
	}
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

	for {
		var req ActionRequest
		err := conn.ReadJSON(&req)
		if err != nil {
			break
		}

		// Routing สบายตาขึ้นมาก
		switch req.Action {
		case "email_register":
			handleEmailRegister(conn, req)
		case "login":
			handleLogin(conn, req, &loggedInUserID)
		case "google_login":
			handleGoogleLogin(conn, req, &loggedInUserID)
		case "register_connection":
			loggedInUserID = req.UserID
			sendHistoryToClient(conn, loggedInUserID)

			mutex.Lock()
			userConnections[loggedInUserID] = conn
			mutex.Unlock()

			fmt.Println("User registered:", loggedInUserID)
		case "send_message":
			handleSendMessage(req)
		case "create_post":
			handleCreatePost(req)
		case "toggle_like":
			handleLike(conn, req, loggedInUserID)
		case "toggle_repost":
			handleRepost(conn, req, loggedInUserID)
		case "toggle_bookmark":
			handleBookmark(conn, req, loggedInUserID)
		case "get_chat_history":
			handleGetChatHistory(conn, req)
		case "update_profile":
			handleUpdateProfile(conn, req)
		case "delete_post":
			handleDeletePost(conn, req)
		case "delete_message":
			handleDeleteMessage(conn, req)

		default:
			sendErrorToClient(conn, "Unknown action")
		}
	}
}
