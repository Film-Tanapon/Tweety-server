package main

import (
	"database/sql"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/lib/pq"
)

var db *sql.DB

func initDB() {
	connStr := os.Getenv("DB_URL")
	var err error
	db, err = sql.Open("postgres", connStr)
	if err != nil {
		log.Fatal("Error opening database:", err)
	}

	if err = db.Ping(); err != nil {
		log.Fatal("Cannot connect to Database:", err)
	}
	fmt.Println("✅ Connected to Database successfully!")
}

// ======================================================================USER========================================================================//

func getOrCreateUserByEmail(email string, username string) (int, error) {
	var userID int
	err := db.QueryRow("SELECT id FROM users WHERE email = $1", email).Scan(&userID)
	if err == sql.ErrNoRows {
		err = db.QueryRow("INSERT INTO users (email, username, password_hash) VALUES ($1, $2, $3) RETURNING id", email, username, "GOOGLE_OAUTH").Scan(&userID)
		return userID, err
	}
	return userID, err
}

func getUserByID(userID int) (*User, error) {
	var user User
	var profileImage, coverImage sql.NullString

	err := db.QueryRow(`
		SELECT id, email, username, profile_image_url, cover_image_url, created_at 
		FROM users WHERE id = $1`, userID).
		Scan(&user.ID, &user.Email, &user.Username, &profileImage, &coverImage, &user.CreatedAt)

	if err != nil {
		return nil, err
	}

	user.ProfileImageURL = profileImage.String
	user.CoverImageURL = coverImage.String

	return &user, nil
}

func updateUserProfile(userID int, username string, profileImageURL string, coverImageURL string) error {
	res, err := db.Exec(`
		UPDATE users 
		SET username = $1, profile_image_url = $2, cover_image_url = $3 
		WHERE id = $4`, username, profileImageURL, coverImageURL, userID)
	if err != nil {
		return err
	}

	rowsAffected, _ := res.RowsAffected()
	if rowsAffected == 0 {
		return fmt.Errorf("user not found")
	}
	return nil
}

func deleteUser(userID int) error {
	_, err := db.Exec("DELETE FROM users WHERE id = $1", userID)
	return err
}

// ======================================================================POST========================================================================//
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

func updatePost(postID int, userID int, newContent string) error {
	res, err := db.Exec(`
		UPDATE posts 
		SET content = $1 
		WHERE id = $2 AND user_id = $3`, newContent, postID, userID)
	if err != nil {
		return err
	}

	rowsAffected, _ := res.RowsAffected()
	if rowsAffected == 0 {
		return fmt.Errorf("post not found or user not authorized to update")
	}
	return nil
}

func deletePost(postID int, userID int) error {
	res, err := db.Exec("DELETE FROM posts WHERE id = $1 AND user_id = $2", postID, userID)
	if err != nil {
		return err
	}

	rowsAffected, _ := res.RowsAffected()
	if rowsAffected == 0 {
		return fmt.Errorf("post not found or user not authorized to delete")
	}
	return nil
}

// ======================================================================LIKE========================================================================//
func getFeedPostsWithUser(userID int) ([]map[string]interface{}, error) {
	rows, err := db.Query(`
		SELECT 
			p.id,
			p.content,
			p.created_at,
			u.username,

			(SELECT COUNT(*) FROM likes WHERE post_id = p.id),
			EXISTS(SELECT 1 FROM likes WHERE user_id=$1 AND post_id=p.id),

			(SELECT COUNT(*) FROM reposts WHERE post_id = p.id),
			EXISTS(SELECT 1 FROM reposts WHERE user_id=$1 AND post_id=p.id),

			EXISTS(SELECT 1 FROM bookmarks WHERE user_id=$1 AND post_id=p.id)

		FROM posts p
		JOIN users u ON p.user_id = u.id
		ORDER BY p.created_at DESC
	`, userID)

	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var posts []map[string]interface{}

	for rows.Next() {
		var postID int
		var content, username string
		var createdAt time.Time
		var likesCount, repostsCount int
		var isLiked, isReposted, isBookmarked bool

		err := rows.Scan(
			&postID,
			&content,
			&createdAt,
			&username,
			&likesCount,
			&isLiked,
			&repostsCount,
			&isReposted,
			&isBookmarked,
		)
		if err != nil {
			continue
		}

		posts = append(posts, map[string]interface{}{
			"post_id":       postID,
			"content":       content,
			"created_at":    createdAt,
			"username":      username,
			"likes_count":   likesCount,
			"is_liked":      isLiked,
			"reposts_count": repostsCount,
			"is_reposted":   isReposted,
			"is_bookmarked": isBookmarked,
		})
	}

	return posts, nil
}

func toggleLike(userID int, postID int) (bool, error) {
	var isLiked bool

	err := db.QueryRow("SELECT EXISTS(SELECT 1 FROM likes WHERE user_id=$1 AND post_id=$2)", userID, postID).Scan(&isLiked)
	if err != nil {
		return false, err
	}

	if isLiked {
		_, err = db.Exec("DELETE FROM likes WHERE user_id=$1 AND post_id=$2", userID, postID)
		if err != nil {
			return true, err
		}
		return false, nil

	} else {
		_, err = db.Exec("INSERT INTO likes (user_id, post_id) VALUES ($1, $2)", userID, postID)
		if err != nil {
			return false, err
		}
		return true, nil
	}
}

// ======================================================================REPOST========================================================================//
func toggleRepost(userID int, postID int) (bool, error) {
	var isReposted bool
	err := db.QueryRow("SELECT EXISTS(SELECT 1 FROM reposts WHERE user_id=$1 AND post_id=$2)", userID, postID).Scan(&isReposted)
	if err != nil {
		return false, err
	}

	if isReposted {
		// ยกเลิกการรีโพสต์
		_, err = db.Exec("DELETE FROM reposts WHERE user_id=$1 AND post_id=$2", userID, postID)
		if err != nil {
			return true, err
		}
		return false, nil
	} else {
		// รีโพสต์
		_, err = db.Exec("INSERT INTO reposts (user_id, post_id) VALUES ($1, $2)", userID, postID)
		if err != nil {
			return false, err
		}
		return true, nil
	}
}

// ======================================================================BOOKMARK========================================================================//
func toggleBookmark(userID int, postID int) (bool, error) {
	var isBookmarked bool
	err := db.QueryRow("SELECT EXISTS(SELECT 1 FROM bookmarks WHERE user_id=$1 AND post_id=$2)", userID, postID).Scan(&isBookmarked)
	if err != nil {
		return false, err
	}

	if isBookmarked {
		// ยกเลิกการบันทึก
		_, err = db.Exec("DELETE FROM bookmarks WHERE user_id=$1 AND post_id=$2", userID, postID)
		if err != nil {
			return true, err
		}
		return false, nil
	} else {
		// บันทึกโพสต์
		_, err = db.Exec("INSERT INTO bookmarks (user_id, post_id) VALUES ($1, $2)", userID, postID)
		if err != nil {
			return false, err
		}
		return true, nil
	}
}

// ======================================================================MESSAGE========================================================================//
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

func getChatHistory(user1ID int, user2ID int) ([]Message, error) {
	rows, err := db.Query(`
		SELECT id, sender_id, receiver_id, content, image_url, is_read, created_at 
		FROM messages 
		WHERE (sender_id = $1 AND receiver_id = $2) 
		   OR (sender_id = $2 AND receiver_id = $1)
		ORDER BY created_at ASC`, user1ID, user2ID)

	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var history []Message
	for rows.Next() {
		var msg Message
		var content, imgURL sql.NullString

		if err := rows.Scan(&msg.ID, &msg.SenderID, &msg.ReceiverID, &content, &imgURL, &msg.IsRead, &msg.CreatedAt); err == nil {

			msg.Content = content.String

			if imgURL.Valid {
				url := imgURL.String
				msg.ImageURL = &url
			} else {
				msg.ImageURL = nil
			}

			history = append(history, msg)
		}
	}

	if history == nil {
		history = []Message{}
	}
	return history, nil
}

func deleteMessage(msgID int, senderID int) error {
	res, err := db.Exec("DELETE FROM messages WHERE id = $1 AND sender_id = $2", msgID, senderID)
	if err != nil {
		return err
	}

	rowsAffected, _ := res.RowsAffected()
	if rowsAffected == 0 {
		return fmt.Errorf("message not found or user not authorized to delete")
	}
	return nil
}

// ======================================================================COMMENT========================================================================//
func getCommentsByPostID(parentID int) ([]PostFeed, error) {
	rows, err := db.Query(`
		SELECT p.id, p.user_id, u.username, COALESCE(u.profile_image_url, ''), 
		       p.content, COALESCE(p.image_urls, '{}'), p.parent_post_id, 
		       (SELECT COUNT(*) FROM likes WHERE post_id = p.id) as like_count, p.created_at 
		FROM posts p 
		JOIN users u ON p.user_id = u.id 
		WHERE p.parent_post_id = $1 
		ORDER BY p.created_at ASC`, parentID)

	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var comments []PostFeed
	for rows.Next() {
		var post PostFeed
		var imgURLs pq.StringArray
		if err := rows.Scan(&post.PostID, &post.UserID, &post.Username, &post.ProfileImageURL, &post.Content, &imgURLs, &post.ParentPostID, &post.LikeCount, &post.CreatedAt); err == nil {
			post.ImageURLs = []string(imgURLs)
			comments = append(comments, post)
		}
	}
	if comments == nil {
		comments = []PostFeed{}
	}
	return comments, nil
}
