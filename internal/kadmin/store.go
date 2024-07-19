package kadmin

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"sync"
	"time"

	"github.com/scorpio-id/kerberos/internal/config"
)

type Store struct {
	key      []byte
	block    cipher.Block
	gcm      cipher.AEAD
	rotation time.Duration
	data     map[string]Metadata
	mu       sync.RWMutex
}

type Metadata struct {
	clientID string
	encpass  string
	created  time.Time
	expires  time.Time
}

// TODO - implement a store which reads a persistent AES256 key
func NewStore(cfg config.Config) (*Store, error) {
	// start by generating a new AES256 key
	key := make([]byte, 32)

	// ensure key is readable
	_, err := rand.Reader.Read(key) 
	if err != nil {
		return nil, err
	}

	// create a block cipher
	block, err := aes.NewCipher(key)
    if err != nil {
       return nil, err
    }

	// Galois, counter mode
	gcm, err := cipher.NewGCM(block)
	if err != nil {
    	return nil, err
	}

	// initialize data map
	data := make(map[string]Metadata)

	// parse duration for password rotation
	rotation, err := time.ParseDuration(cfg.Realm.PasswordRotation)
	if err != nil {
		return nil, err
	}

	// create data store
	store := Store {
		key: key,
		block: block,
		gcm: gcm,
		rotation: rotation,
		data: data,
	}

	return &store, nil
}

// remember to generate nonce before encryption!
func (store *Store) Add(clientID string, principal string, password string) {
	store.mu.Lock()
	defer store.mu.Unlock()

	// generate nonce to encrypt password
	nonce := make([]byte, store.gcm.NonceSize())

	// encrypt
	ciphertext := store.gcm.Seal(nonce, nonce, []byte(password), nil)

	// convert ciphertext to hexadecimal
	encpass := hex.EncodeToString(ciphertext)

	metadata := Metadata {
		clientID: clientID,
		encpass: encpass,
		created: time.Now(),
		expires: time.Now().Add(store.rotation),
	}

	// add principal to data store, key = principal name / value = metadata
	store.data[principal] = metadata
} 