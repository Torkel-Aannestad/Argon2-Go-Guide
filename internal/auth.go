package auth

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

type Params struct {
	Memory      uint32
	Iterations  uint32
	Parallelism uint8
	SaltLength  uint32
	KeyLength   uint32
}

var DefaultParams = &Params{
	Memory:      64 * 1024,
	Iterations:  2,
	Parallelism: 1,
	SaltLength:  16,
	KeyLength:   32,
}

var (
	ErrInvalidHash         = errors.New("the encoded hash is not in the correct format")
	ErrIncompatibleVersion = errors.New("incompatible version of argon2")
)

func generateRandomBytes(n uint32) ([]byte, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	if err != nil {
		return nil, err
	}

	return b, nil
}

func GenerateFromPassword(password string, secretKey []byte, p *Params) (encryptedHash string, err error) {
	salt, err := generateRandomBytes(p.SaltLength)
	if err != nil {
		return "", err
	}

	hash := argon2.IDKey([]byte(password), []byte(salt), p.Iterations, p.Memory, p.Parallelism, p.KeyLength)

	base64Salt := base64.RawStdEncoding.EncodeToString(salt)
	base64Hash := base64.RawStdEncoding.EncodeToString(hash)

	encodedHash := fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s", argon2.Version, p.Memory, p.Iterations, p.Parallelism, base64Salt, base64Hash)

	encryptedHash, err = encrypt(encodedHash, secretKey)
	if err != nil {
		return "", err
	}

	return encryptedHash, nil
}

func ComparePasswordAndHash(password, encryptedHash string, secretKey []byte) (match bool, err error) {
	encodedHash, err := decrypt(encryptedHash, secretKey)
	if err != nil {
		return false, err
	}
	p, salt, hash, err := decodeHash(encodedHash)
	if err != nil {
		return false, err
	}

	inputHash := argon2.IDKey([]byte(password), []byte(salt), p.Iterations, p.Memory, p.Parallelism, p.KeyLength)

	if subtle.ConstantTimeCompare(hash, inputHash) == 1 {
		return true, nil
	} else {
		return false, nil
	}

}

func decodeHash(encodedHash string) (p *Params, salt, hash []byte, err error) {
	parts := strings.Split(encodedHash, "$")
	if len(parts) != 6 {
		return nil, nil, nil, ErrInvalidHash
	}

	var version int
	_, err = fmt.Sscanf(parts[2], "v=%d", &version)
	if err != nil {
		return nil, nil, nil, err
	}
	if version != argon2.Version {
		return nil, nil, nil, ErrIncompatibleVersion
	}

	p = &Params{}
	_, err = fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &p.Memory, &p.Iterations, &p.Parallelism)
	if err != nil {
		return nil, nil, nil, err
	}

	salt, err = base64.RawStdEncoding.Strict().DecodeString(parts[4])
	if err != nil {
		return nil, nil, nil, err
	}
	p.SaltLength = uint32(len(salt))

	hash, err = base64.RawStdEncoding.Strict().DecodeString(parts[5])
	if err != nil {
		return nil, nil, nil, err
	}
	p.KeyLength = uint32(len(hash))

	return p, salt, hash, nil
}

func encrypt(encodedHash string, secretKey []byte) (encryptedHash string, err error) {
	cipherBlock, err := aes.NewCipher(secretKey)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(cipherBlock)
	if err != nil {
		return "", err
	}

	nonce, err := generateRandomBytes(uint32(gcm.NonceSize()))
	if err != nil {
		return "", err
	}

	cipherText := gcm.Seal(nonce, nonce, []byte(encodedHash), nil)
	encryptedHash = base64.RawStdEncoding.EncodeToString(cipherText)

	return encryptedHash, nil
}

func decrypt(encryptedData string, secretKey []byte) (string, error) {
	cipherBlock, err := aes.NewCipher(secretKey)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(cipherBlock)
	if err != nil {
		return "", err
	}

	ciphertext, err := base64.RawStdEncoding.DecodeString(encryptedData)
	if err != nil {
		return "", err
	}

	if len(ciphertext) < gcm.NonceSize() {
		return "", err
	}

	nonce, cipherData := ciphertext[:gcm.NonceSize()], ciphertext[gcm.NonceSize():]

	encodedHash, err := gcm.Open(nil, nonce, cipherData, nil)
	if err != nil {
		return "", err
	}

	return string(encodedHash), nil
}
