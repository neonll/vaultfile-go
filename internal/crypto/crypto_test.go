package crypto

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"testing"
)

func TestGenerateRSAKey(t *testing.T) {
	key, err := GenerateRSAKey(RSAKeySize)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}

	if key.Size()*8 < RSAKeySize {
		t.Fatalf("generated key size is too small: got %d bits, want at least %d bits", key.Size()*8, RSAKeySize)
	}
}

func TestGenerateRSAKeyTooSmall(t *testing.T) {
	_, err := GenerateRSAKey(1024)
	if err == nil {
		t.Fatal("expected error when generating key with insufficient bits")
	}
}

func TestRSAEncryptDecryptOAEP(t *testing.T) {
	// Generate a test key
	privateKey, err := rsa.GenerateKey(rand.Reader, RSAKeySize)
	if err != nil {
		t.Fatalf("failed to generate test key: %v", err)
	}

	testData := []byte("Hello, World!")

	// Encrypt
	ciphertext, err := EncryptRSAOAEP(&privateKey.PublicKey, testData)
	if err != nil {
		t.Fatalf("failed to encrypt data: %v", err)
	}

	// Decrypt
	plaintext, err := DecryptRSAOAEP(privateKey, ciphertext)
	if err != nil {
		t.Fatalf("failed to decrypt data: %v", err)
	}

	if string(plaintext) != string(testData) {
		t.Fatalf("decrypted data doesn't match original: got %q, want %q", string(plaintext), string(testData))
	}
}

func TestAESGCMEncryptDecrypt(t *testing.T) {
	key, err := GenerateAESKey()
	if err != nil {
		t.Fatalf("failed to generate AES key: %v", err)
	}

	testData := []byte("This is a test message for AES-GCM encryption")

	// Encrypt
	ciphertext, err := EncryptAESGCM(key, testData)
	if err != nil {
		t.Fatalf("failed to encrypt data: %v", err)
	}

	// Decrypt
	plaintext, err := DecryptAESGCM(key, ciphertext)
	if err != nil {
		t.Fatalf("failed to decrypt data: %v", err)
	}

	if string(plaintext) != string(testData) {
		t.Fatalf("decrypted data doesn't match original: got %q, want %q", string(plaintext), string(testData))
	}
}

func TestEncryptSecretUTF8(t *testing.T) {
	secret := "This is a secret message"

	result, err := EncryptSecretUTF8(secret)
	if err != nil {
		t.Fatalf("failed to encrypt secret: %v", err)
	}

	if len(result.AESKey) != AESKeySize {
		t.Fatalf("AES key size is incorrect: got %d, want %d", len(result.AESKey), AESKeySize)
	}

	if result.EncryptedData == "" {
		t.Fatal("encrypted data is empty")
	}

	// Verify we can decrypt it
	decrypted, err := DecryptSecret(result.EncryptedData, result.AESKey)
	if err != nil {
		t.Fatalf("failed to decrypt secret: %v", err)
	}

	if decrypted != secret {
		t.Fatalf("decrypted secret doesn't match original: got %q, want %q", decrypted, secret)
	}
}

func TestEncryptSecretBase64(t *testing.T) {
	originalData := []byte("This is binary data: \x00\x01\x02\x03")
	secretBase64 := base64.StdEncoding.EncodeToString(originalData)

	result, err := EncryptSecretBase64(secretBase64)
	if err != nil {
		t.Fatalf("failed to encrypt secret: %v", err)
	}

	if len(result.AESKey) != AESKeySize {
		t.Fatalf("AES key size is incorrect: got %d, want %d", len(result.AESKey), AESKeySize)
	}

	// Verify we can decrypt it
	decrypted, err := DecryptSecret(result.EncryptedData, result.AESKey)
	if err != nil {
		t.Fatalf("failed to decrypt secret: %v", err)
	}

	if decrypted != string(originalData) {
		t.Fatalf("decrypted secret doesn't match original: got %q, want %q", decrypted, string(originalData))
	}
}

func TestEncryptSecretBase64Invalid(t *testing.T) {
	invalidBase64 := "This is not valid base64!!!"

	_, err := EncryptSecretBase64(invalidBase64)
	if err == nil {
		t.Fatal("expected error when encrypting invalid base64")
	}
}

func TestDecryptSecretInvalidBase64(t *testing.T) {
	key, err := GenerateAESKey()
	if err != nil {
		t.Fatalf("failed to generate AES key: %v", err)
	}

	invalidBase64 := "This is not valid base64!!!"

	_, err = DecryptSecret(invalidBase64, key)
	if err == nil {
		t.Fatal("expected error when decrypting invalid base64")
	}
}

func TestDecryptSecretWrongKey(t *testing.T) {
	secret := "This is a secret message"

	// Encrypt with one key
	result, err := EncryptSecretUTF8(secret)
	if err != nil {
		t.Fatalf("failed to encrypt secret: %v", err)
	}

	// Try to decrypt with a different key
	wrongKey, err := GenerateAESKey()
	if err != nil {
		t.Fatalf("failed to generate wrong key: %v", err)
	}

	_, err = DecryptSecret(result.EncryptedData, wrongKey)
	if err == nil {
		t.Fatal("expected error when decrypting with wrong key")
	}
}
