package cryptography

import (
	"bytes"
	"errors"
	"testing"
)

func TestEncryptDecryptMessageRoundTrip(t *testing.T) {
	privateKey, publicKey, err := GenerateKeys(2048)
	if err != nil {
		t.Fatal(err)
	}

	message := []byte("integration payload: 192.0.2.1")
	ciphertext, err := EncryptMessage(publicKey, message)
	if err != nil {
		t.Fatalf("EncryptMessage() error = %v", err)
	}
	if bytes.Equal(ciphertext, message) {
		t.Fatal("EncryptMessage() returned plaintext")
	}

	decrypted, err := DecryptMessage(privateKey, ciphertext)
	if err != nil {
		t.Fatalf("DecryptMessage() error = %v", err)
	}
	if !bytes.Equal(decrypted, message) {
		t.Errorf("decrypted = %q, want %q", decrypted, message)
	}
}

func TestDecryptMessageRejectsInvalidData(t *testing.T) {
	privateKey, _, err := GenerateKeys(2048)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := DecryptMessage(privateKey, []byte("short")); !errors.Is(err, ErrWrongMessageLen) {
		t.Fatalf("error = %v, want ErrWrongMessageLen", err)
	}

	invalid := make([]byte, privateKey.Size()+12)
	if _, err := DecryptMessage(privateKey, invalid); err == nil {
		t.Fatal("DecryptMessage() accepted an invalid encrypted key")
	}
}

func TestAESHelpersRejectInvalidInputs(t *testing.T) {
	if _, _, err := encryptWithAES([]byte("too short"), []byte("payload")); err == nil {
		t.Fatal("encryptWithAES() accepted an invalid key")
	}
	if _, err := decryptWithAES([]byte("too short"), make([]byte, 12), []byte("payload")); err == nil {
		t.Fatal("decryptWithAES() accepted an invalid key")
	}
}
