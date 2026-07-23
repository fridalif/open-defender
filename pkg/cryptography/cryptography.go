package cryptography

import (
	"crypto/aes"
	"crypto/cipher"
	cryptorand "crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"fmt"
	"io"
)

func EncryptMessage(publicKey *rsa.PublicKey, message []byte) ([]byte, error) {
	aesKey := make([]byte, 32)
	if _, err := io.ReadFull(cryptorand.Reader, aesKey); err != nil {
		return nil, fmt.Errorf("cryptography->EncryptMessage() generating aes key: %w", err)
	}

	encryptedData, iv, err := encryptWithAES(aesKey, message)
	if err != nil {
		return nil, fmt.Errorf("cryptography->EncryptMessage()->encryptWithAes(): %w", err)
	}

	encryptedAESKey, err := rsa.EncryptOAEP(
		sha256.New(),
		cryptorand.Reader,
		publicKey,
		aesKey,
		nil,
	)
	if err != nil {
		return nil, fmt.Errorf("cryptography->EncryptMessage()->resa.EncryptOAEP(): %w", err)
	}

	result := append(encryptedAESKey, iv...)
	result = append(result, encryptedData...)

	return result, nil
}

func DecryptMessage(privateKey *rsa.PrivateKey, cipherData []byte) ([]byte, error) {
	keySize := privateKey.Size()
	if len(cipherData) < keySize+12 {
		return nil, fmt.Errorf("cryptography->DecryptMessage(): %w", ErrWrongMessageLen)
	}

	encryptedAESKey := cipherData[:keySize]
	iv := cipherData[keySize : keySize+12]
	encryptedData := cipherData[keySize+12:]

	aesKey, err := rsa.DecryptOAEP(
		sha256.New(),
		cryptorand.Reader,
		privateKey,
		encryptedAESKey,
		nil,
	)
	if err != nil {
		return nil, fmt.Errorf("cryptography->DecryptMessage()->rsa.DEcryptOAEP(): %w", err)
	}

	message, err := decryptWithAES(aesKey, iv, encryptedData)
	if err != nil {
		return nil, fmt.Errorf("cryptography->DecryptMessage()->decryptWithAES(): %w", err)
	}

	return message, nil
}

func encryptWithAES(key []byte, plaintext []byte) ([]byte, []byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, err
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, err
	}

	nonce := make([]byte, aesGCM.NonceSize())
	if _, err := io.ReadFull(cryptorand.Reader, nonce); err != nil {
		return nil, nil, err
	}

	ciphertext := aesGCM.Seal(nil, nonce, plaintext, nil)

	return ciphertext, nonce, nil
}

func decryptWithAES(key []byte, nonce []byte, ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	plaintext, err := aesGCM.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

func GenerateKeys(bits int) (*rsa.PrivateKey, *rsa.PublicKey, error) {
	privateKey, err := rsa.GenerateKey(cryptorand.Reader, bits)
	if err != nil {
		return nil, nil, err
	}
	return privateKey, &privateKey.PublicKey, nil
}
