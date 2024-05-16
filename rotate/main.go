package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/dgrijalva/jwt-go"
)

var (
	privateKey *rsa.PrivateKey
	publicKeys []*rsa.PublicKey
	index      int // Index to keep track of the current public key
	mu         sync.Mutex
)

const maxKeys = 3 // Maximum number of public keys to maintain

func init() {
	var err error
	privateKey, err = rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	publicKeys = []*rsa.PublicKey{&privateKey.PublicKey}
	index = 0 // Start with the first key

	go rotatePublicKeys()
}

func main() {
	http.HandleFunc("/generate", generateToken)
	http.HandleFunc("/verify", verifyToken)
	http.HandleFunc("/public-keys", getPublicKeys)
	http.ListenAndServe(":8080", nil)
}

func generateToken(w http.ResponseWriter, r *http.Request) {
	// Use the latest private key for signing
	token := jwt.New(jwt.SigningMethodRS256)
	token.Claims = jwt.StandardClaims{
		ExpiresAt: time.Now().Add(5 * time.Minute).Unix(), // Example: token expires in 5 minutes
		Issuer:    "your-issuer",
	}
	tokenString, err := token.SignedString(privateKey)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Write([]byte(tokenString))
}

func verifyToken(w http.ResponseWriter, r *http.Request) {
	tokenString := r.Header.Get("Authorization")
	if tokenString == "" {
		http.Error(w, "Authorization header missing", http.StatusBadRequest)
		return
	}

	// Remove "Bearer " prefix from token string
	tokenString = tokenString[len("Bearer "):]

	mu.Lock()
	defer mu.Unlock()

	for _, publicKey := range publicKeys {
		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			return publicKey, nil
		})
		if err == nil && token.Valid {
			fmt.Println("Token is valid")
			w.Write([]byte("Token is valid"))
			return
		}
	}

	fmt.Println("Invalid token")
	http.Error(w, "Invalid token", http.StatusUnauthorized)
}

func getPublicKeys(w http.ResponseWriter, r *http.Request) {
	mu.Lock()
	defer mu.Unlock()

	for _, publicKey := range publicKeys {
		pemBytes := pem.EncodeToMemory(&pem.Block{
			Type:  "RSA PUBLIC KEY",
			Bytes: x509.MarshalPKCS1PublicKey(publicKey),
		})
		w.Write(pemBytes)
		w.Write([]byte("\n"))
	}
}

func rotatePublicKeys() {
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			newPrivateKey, err := rsa.GenerateKey(rand.Reader, 2048)
			if err != nil {
				fmt.Println("Error generating new private key:", err)
				continue
			}
			newPublicKey := &newPrivateKey.PublicKey

			mu.Lock()
			if len(publicKeys) < maxKeys {
				publicKeys = append(publicKeys, newPublicKey)
			} else {
				// Replace the oldest public key with the new one
				publicKeys[index] = newPublicKey
				index = (index + 1) % maxKeys // Move index circularly
			}
			// Update the privateKey variable with the new private key
			privateKey = newPrivateKey
			mu.Unlock()

			fmt.Println("Rotated public keys")
		}
	}
}
