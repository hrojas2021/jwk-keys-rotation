package main

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/gorilla/mux"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

var (
	publicKeys  jwk.Set
	privateKeys map[string]*rsa.PrivateKey
	mutex       sync.Mutex
)

func generateKeyPair() (*rsa.PrivateKey, jwk.Key, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}

	key, err := jwk.FromRaw(privateKey.PublicKey)
	if err != nil {
		return nil, nil, err
	}

	kid := fmt.Sprintf("key-%d", time.Now().Unix())
	key.Set(jwk.KeyIDKey, kid)
	key.Set(jwk.AlgorithmKey, jwa.RS256)

	return privateKey, key, nil
}

func rotateKeys() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for {
		<-ticker.C

		privateKey1, publicKey1, err := generateKeyPair()
		if err != nil {
			log.Printf("Error generating key pair: %v", err)
			continue
		}

		privateKey2, publicKey2, err := generateKeyPair()
		if err != nil {
			log.Printf("Error generating key pair: %v", err)
			continue
		}

		mutex.Lock()
		privateKeys = map[string]*rsa.PrivateKey{
			publicKey1.KeyID(): privateKey1,
			publicKey2.KeyID(): privateKey2,
		}
		publicKeys = jwk.NewSet()
		publicKeys.AddKey(publicKey1)
		publicKeys.AddKey(publicKey2)
		mutex.Unlock()

		savePrivateKeysToFile()
	}
}

func savePrivateKeysToFile() {
	for kid, privateKey := range privateKeys {
		fileName := fmt.Sprintf("private_key_%s.pem", kid)
		file, err := os.Create(fileName)
		if err != nil {
			log.Printf("Error creating PEM file: %v", err)
			continue
		}
		defer file.Close()

		pemKey, err := jwk.FromRaw(privateKey)
		if err != nil {
			log.Printf("Error creating JWK from private key: %v", err)
			continue
		}

		pemKey.Set(jwk.AlgorithmKey, jwa.RS256)
		pemKey.Set(jwk.KeyUsageKey, "sig")

		json.NewEncoder(file).Encode(pemKey)
	}
}

func generateTokenHandler(w http.ResponseWriter, r *http.Request) {
	mutex.Lock()
	var privateKey *rsa.PrivateKey
	var kid string
	for k, v := range privateKeys {
		privateKey = v
		kid = k
		break
	}
	mutex.Unlock()

	token := jwt.New()
	token.Set(jwt.SubjectKey, "user123")
	token.Set(jwt.IssuedAtKey, time.Now())
	token.Set(jwt.ExpirationKey, time.Now().Add(5*time.Minute))
	token.Set(jwt.JwtIDKey, kid)

	signed, err := jwt.Sign(token, jwt.WithKey(jwa.RS256, privateKey))
	if err != nil {
		http.Error(w, fmt.Sprintf("Error signing token: %v", err), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write(signed)
}

func verifyTokenHandler(w http.ResponseWriter, r *http.Request) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		http.Error(w, "Authorization header is required", http.StatusBadRequest)
		return
	}

	var tokenString string
	fmt.Sscanf(authHeader, "Bearer %s", &tokenString)
	if tokenString == "" {
		http.Error(w, "Invalid token", http.StatusBadRequest)
		return
	}

	mutex.Lock()
	keys := publicKeys
	mutex.Unlock()

	var verified bool

	ctx := r.Context()
	it := keys.Keys(ctx)

	for {
		ok := it.Next(ctx)
		if !ok {
			break // Exit loop when there are no more keys
		}

		key := it.Pair().Value

		token, err := jwt.Parse([]byte(tokenString), jwt.WithKey(jwa.RS256, key))
		if err == nil {
			verified = true
			break // Exit loop if token is verified
		}
		fmt.Println("TOKEN", token)
	}

	if !verified {
		http.Error(w, fmt.Sprintf("Error verifying token: %v", nil), http.StatusUnauthorized)
		return
	}

	response := map[string]interface{}{
		"verified": true,
	}
	json.NewEncoder(w).Encode(response)
}

func publicKeysHandler(w http.ResponseWriter, r *http.Request) {
	mutex.Lock()
	keys := publicKeys
	mutex.Unlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(keys)
}

func main() {
	privateKey1, publicKey1, err := generateKeyPair()
	if err != nil {
		log.Fatalf("Error generating key pair: %v", err)
	}

	privateKey2, publicKey2, err := generateKeyPair()
	if err != nil {
		log.Fatalf("Error generating key pair: %v", err)
	}

	privateKeys = map[string]*rsa.PrivateKey{
		publicKey1.KeyID(): privateKey1,
		publicKey2.KeyID(): privateKey2,
	}
	publicKeys = jwk.NewSet()
	publicKeys.AddKey(publicKey1)
	publicKeys.AddKey(publicKey2)

	go rotateKeys()

	r := mux.NewRouter()
	r.HandleFunc("/generate", generateTokenHandler).Methods("GET")
	r.HandleFunc("/verify", verifyTokenHandler).Methods("GET")
	r.HandleFunc("/public-keys", publicKeysHandler).Methods("GET")

	http.Handle("/", r)
	log.Println("Server started on :8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
