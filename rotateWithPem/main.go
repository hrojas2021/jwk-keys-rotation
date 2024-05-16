package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/dgrijalva/jwt-go"
)

var (
	privateKeyFile = "private_key.pem"
	privateKey     *rsa.PrivateKey
	publicKeys     []*rsa.PublicKey
	index          int // Index to keep track of the current public key
	mu             sync.Mutex
)

const maxKeys = 3 // Maximum number of public keys to maintain

func main() {
	// Load private key from PEM file or generate a new one if the file doesn't exist
	if _, err := os.Stat(privateKeyFile); os.IsNotExist(err) {
		privateKey, err = rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			panic(err)
		}
		savePrivateKey(privateKey)
	} else {
		privateKey, err = loadPrivateKey()
		if err != nil {
			panic(err)
		}
	}
	publicKeys = []*rsa.PublicKey{&privateKey.PublicKey}

	go rotatePublicKeys()

	http.HandleFunc("/generate", generateToken)
	http.HandleFunc("/verify", verifyToken)
	http.HandleFunc("/public-keys", getPublicKeys)
	fmt.Println("Server listening on port 8080")
	http.ListenAndServe(":8080", nil)
}

func generateToken(w http.ResponseWriter, r *http.Request) {
	token := jwt.New(jwt.SigningMethodRS256)
	token.Claims = jwt.StandardClaims{
		ExpiresAt: time.Now().Add(5 * time.Minute).Unix(),
		Issuer:    "rotate-implementer",
		Audience:  "test-development",
		IssuedAt:  time.Now().Unix(),
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

	for range ticker.C {
		newPrivateKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			fmt.Println("Error generating new private key:", err)
			continue
		}
		// TODO: put .temp the previous pem file
		err = savePrivateKey(newPrivateKey) // Save the new private key to the PEM file
		if err != nil {
			fmt.Println("Error saving new private key:", err)
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

func savePrivateKey(key *rsa.PrivateKey) error {
	// Encode private key to PEM format
	pemKey := &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}

	// Open file for writing
	file, err := os.Create(privateKeyFile)
	if err != nil {
		return err
	}
	defer file.Close()

	// Write PEM data to file
	err = pem.Encode(file, pemKey)
	if err != nil {
		return err
	}

	return nil
}

func loadPrivateKey() (*rsa.PrivateKey, error) {
	file, err := os.Open(privateKeyFile)
	if err != nil {
		fmt.Println(err)
		return nil, err
	}
	defer file.Close()

	// Read PEM data from file
	pemData, err := io.ReadAll(file)
	if err != nil {
		fmt.Println(err)
		return nil, err
	}

	// Decode PEM data
	block, _ := pem.Decode(pemData)
	if block == nil || block.Type != "RSA PRIVATE KEY" {
		return nil, fmt.Errorf("failed to decode PEM block containing private key")
	}
	// Parse the RSA private key
	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	return key, nil
}
