package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/dgrijalva/jwt-go"
	_ "github.com/glebarez/go-sqlite"
	"github.com/gorilla/websocket"
	"github.com/rs/cors"
	"golang.org/x/crypto/bcrypt"
)

var jwtKey = []byte("my_secret_key")
var db *sql.DB

var clients = make(map[string][]*websocket.Conn)
var broadcast = make(chan Message)

type Credentials struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type Claims struct {
	Username string `json:"username"`
	jwt.StandardClaims
}

type Message struct {
	Username string `json:"username"`
	Message  string `json:"message"`
	Room     string `json:"room"`
}

// upgrader is used to upgrade the HTTP connection to a WebSocket connection
var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool {
		return true // Allow connection from any origin
	},
}

func initDB() {
	var err error
	db, err = sql.Open("sqlite", "chatapp.db")
	if err != nil {
		log.Fatal(err)
	}

	createTable := `
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL UNIQUE,
        password TEXT NOT NULL
    );`
	if _, err = db.Exec(createTable); err != nil {
		log.Fatal(err)
	}

	log.Println("Database connected and tables created!")
}

func registerUser(creds Credentials) error {
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(creds.Password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}

	_, err = db.Exec("INSERT INTO users (username, password) VALUES (?, ?)", creds.Username, string(hashedPassword))
	return err
}

func checkUserCredentials(creds Credentials) bool {
	var storedPassword string
	err := db.QueryRow("SELECT password FROM users WHERE username = ?", creds.Username).Scan(&storedPassword)
	if err != nil {
		log.Println("Username not found:", creds.Username)
		return false
	}

	err = bcrypt.CompareHashAndPassword([]byte(storedPassword), []byte(creds.Password))
	return err == nil
}

func registerHandler(w http.ResponseWriter, r *http.Request) {
	var creds Credentials
	if err := json.NewDecoder(r.Body).Decode(&creds); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	if err := registerUser(creds); err != nil {
		if err.Error() == "UNIQUE constraint failed: users.username" {
			w.WriteHeader(http.StatusConflict)
		} else {
			w.WriteHeader(http.StatusInternalServerError)
		}
		return
	}

	w.WriteHeader(http.StatusOK)
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	var creds Credentials
	if err := json.NewDecoder(r.Body).Decode(&creds); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	if !checkUserCredentials(creds) {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	expirationTime := time.Now().Add(5 * time.Minute)
	claims := &Claims{
		Username: creds.Username,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: expirationTime.Unix(),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(jwtKey)
	if err != nil {
		log.Println("Error signing token:", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:    "token",
		Value:   tokenString,
		Expires: expirationTime,
	})

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"token": tokenString})
}

func handleConnections(w http.ResponseWriter, r *http.Request) {
	// Get username and room from the query parameters
	username := r.URL.Query().Get("username")
	room := r.URL.Query().Get("room")

	// Upgrade the HTTP server connection to the WebSocket protocol
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Println("Error upgrading to websocket:", err)
		return
	}
	defer conn.Close()

	if _, ok := clients[room]; !ok {
		clients[room] = []*websocket.Conn{conn}
	} else {
		clients[room] = append(clients[room], conn)
	}

	fmt.Println(clients)

	fmt.Printf("%s joined %s\n", username, room)

	for {
		_, message, err := conn.ReadMessage()
		if err != nil {
			log.Printf("error: %v", err)
			delete(clients, room)
			break
		}

		broadcast <- Message{Username: username, Message: string(message), Room: room}
	}
}
func handleMessages() {
	for {
		msg := <-broadcast

		log.Printf("%s in %s: %s\n", msg.Username, msg.Room, msg.Message)

		for _, conn := range clients[msg.Room] {
			err := conn.WriteMessage(websocket.TextMessage, []byte(msg.Username+": "+msg.Message))
			if err != nil {
				log.Printf("Websocket error: %v", err)
				conn.Close()
			}
		}
	}
}

func main() {
	initDB()
	http.HandleFunc("/register", registerHandler)
	http.HandleFunc("/login", loginHandler)
	http.HandleFunc("/ws", handleConnections)

	c := cors.New(cors.Options{
		AllowedOrigins:   []string{"*"},
		AllowCredentials: true,
	})

	handler := c.Handler(http.DefaultServeMux)

	go handleMessages()

	log.Println("Server started on :8080")
	if err := http.ListenAndServe(":8080", handler); err != nil {
		log.Fatal("ListenAndServe: ", err)
	}
}
