package vault

import (
	"os"
	"path/filepath"
	"testing"

	"neonll.com/vaultfile-go/internal/crypto"
)

func TestNewVaultfile(t *testing.T) {
	vf := NewVaultfile()
	if vf == nil {
		t.Fatal("NewVaultfile returned nil")
	}

	if len(vf.Keys) != 0 {
		t.Fatalf("expected empty keys, got %d keys", len(vf.Keys))
	}

	if len(vf.Secrets) != 0 {
		t.Fatalf("expected empty secrets, got %d secrets", len(vf.Secrets))
	}
}

func TestGenerateAndSaveKey(t *testing.T) {
	tempDir := t.TempDir()
	keyPath := filepath.Join(tempDir, "test.key")

	err := GenerateAndSaveKey(keyPath)
	if err != nil {
		t.Fatalf("failed to generate and save key: %v", err)
	}

	// Check that both private and public key files exist
	if _, err := os.Stat(keyPath); os.IsNotExist(err) {
		t.Fatal("private key file was not created")
	}

	pubKeyPath := keyPath + ".pub"
	if _, err := os.Stat(pubKeyPath); os.IsNotExist(err) {
		t.Fatal("public key file was not created")
	}

	// Try to load the keys
	privateKey, err := LoadPrivateKey(keyPath)
	if err != nil {
		t.Fatalf("failed to load generated private key: %v", err)
	}

	publicKey, err := LoadPublicKey(pubKeyPath)
	if err != nil {
		t.Fatalf("failed to load generated public key: %v", err)
	}

	// Verify the keys match
	if privateKey.PublicKey.N.Cmp(publicKey.N) != 0 || privateKey.PublicKey.E != publicKey.E {
		t.Fatal("generated private and public keys don't match")
	}
}

func TestLoadNonexistentFile(t *testing.T) {
	_, err := LoadFromFile("nonexistent.vault")
	if err == nil {
		t.Fatal("expected error when loading nonexistent file")
	}

	vaultErr, ok := err.(*VaultfileError)
	if !ok {
		t.Fatalf("expected VaultfileError, got %T", err)
	}

	if vaultErr.Kind != VaultfileNotFound {
		t.Fatalf("expected VaultfileNotFound error, got %v", vaultErr.Kind)
	}
}

func TestLoadPrivateKeyNonexistent(t *testing.T) {
	_, err := LoadPrivateKey("nonexistent.key")
	if err == nil {
		t.Fatal("expected error when loading nonexistent private key")
	}

	vaultErr, ok := err.(*VaultfileError)
	if !ok {
		t.Fatalf("expected VaultfileError, got %T", err)
	}

	if vaultErr.Kind != PrivateKeyNotFound {
		t.Fatalf("expected PrivateKeyNotFound error, got %v", vaultErr.Kind)
	}
}

func TestPublicKeyJSONRoundtrip(t *testing.T) {
	// Generate a test key
	privateKey, err := crypto.GenerateRSAKey(crypto.RSAKeySize)
	if err != nil {
		t.Fatalf("failed to generate test key: %v", err)
	}

	publicKey := &privateKey.PublicKey

	// Convert to JSON
	jsonStr, err := PublicKeyToJSON(publicKey)
	if err != nil {
		t.Fatalf("failed to convert public key to JSON: %v", err)
	}

	// Parse back from JSON
	parsedKey, err := ParsePublicKey(jsonStr)
	if err != nil {
		t.Fatalf("failed to parse public key from JSON: %v", err)
	}

	// Verify they match
	if publicKey.N.Cmp(parsedKey.N) != 0 || publicKey.E != parsedKey.E {
		t.Fatal("public key JSON roundtrip failed")
	}
}

func TestVaultfileWithoutKeys(t *testing.T) {
	vf := NewVaultfile()

	// Try to validate an empty vaultfile
	err := vf.validate()
	if err == nil {
		t.Fatal("expected error when validating vaultfile without keys")
	}

	vaultErr, ok := err.(*VaultfileError)
	if !ok {
		t.Fatalf("expected VaultfileError, got %T", err)
	}

	if vaultErr.Kind != VaultfileMustHaveKeys {
		t.Fatalf("expected VaultfileMustHaveKeys error, got %v", vaultErr.Kind)
	}
}

func TestFullVaultfileWorkflow(t *testing.T) {
	tempDir := t.TempDir()
	vaultfilePath := filepath.Join(tempDir, "test.vault")

	// Generate a test key
	privateKey, err := crypto.GenerateRSAKey(crypto.RSAKeySize)
	if err != nil {
		t.Fatalf("failed to generate test key: %v", err)
	}

	// Create a new vaultfile
	vf := NewVaultfile()

	// Register the key
	keyName := "testkey"
	err = vf.RegisterKey(keyName, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatalf("failed to register key: %v", err)
	}

	// Add a secret
	secretName := "testsecret"
	secretValue := "SECRET_VALUE_12345"
	err = vf.AddSecretUTF8(secretName, secretValue)
	if err != nil {
		t.Fatalf("failed to add secret: %v", err)
	}

	// Save the vaultfile
	err = vf.SaveToFile(vaultfilePath)
	if err != nil {
		t.Fatalf("failed to save vaultfile: %v", err)
	}

	// Load the vaultfile
	loadedVF, err := LoadFromFile(vaultfilePath)
	if err != nil {
		t.Fatalf("failed to load vaultfile: %v", err)
	}

	// Read the secret
	recoveredSecret, err := loadedVF.ReadSecret(secretName, privateKey)
	if err != nil {
		t.Fatalf("failed to read secret: %v", err)
	}

	if recoveredSecret != secretValue {
		t.Fatalf("recovered secret doesn't match: got %q, want %q", recoveredSecret, secretValue)
	}
}

func TestRegisterMultipleKeys(t *testing.T) {
	// Generate two test keys
	privateKey1, err := crypto.GenerateRSAKey(crypto.RSAKeySize)
	if err != nil {
		t.Fatalf("failed to generate first test key: %v", err)
	}

	privateKey2, err := crypto.GenerateRSAKey(crypto.RSAKeySize)
	if err != nil {
		t.Fatalf("failed to generate second test key: %v", err)
	}

	// Create a new vaultfile and register first key
	vf := NewVaultfile()
	err = vf.RegisterKey("key1", &privateKey1.PublicKey, privateKey1)
	if err != nil {
		t.Fatalf("failed to register first key: %v", err)
	}

	// Add a secret
	secretName := "testsecret"
	secretValue := "SECRET_VALUE_12345"
	err = vf.AddSecretUTF8(secretName, secretValue)
	if err != nil {
		t.Fatalf("failed to add secret: %v", err)
	}

	// Register second key (this should re-encrypt the secret)
	err = vf.RegisterKey("key2", &privateKey2.PublicKey, privateKey1)
	if err != nil {
		t.Fatalf("failed to register second key: %v", err)
	}

	// Both keys should be able to read the secret
	recoveredSecret1, err := vf.ReadSecret(secretName, privateKey1)
	if err != nil {
		t.Fatalf("failed to read secret with first key: %v", err)
	}

	recoveredSecret2, err := vf.ReadSecret(secretName, privateKey2)
	if err != nil {
		t.Fatalf("failed to read secret with second key: %v", err)
	}

	if recoveredSecret1 != secretValue || recoveredSecret2 != secretValue {
		t.Fatal("secrets don't match expected value")
	}
}

func TestDeregisterKey(t *testing.T) {
	// Generate two test keys
	privateKey1, err := crypto.GenerateRSAKey(crypto.RSAKeySize)
	if err != nil {
		t.Fatalf("failed to generate first test key: %v", err)
	}

	privateKey2, err := crypto.GenerateRSAKey(crypto.RSAKeySize)
	if err != nil {
		t.Fatalf("failed to generate second test key: %v", err)
	}

	// Create vaultfile with both keys
	vf := NewVaultfile()
	err = vf.RegisterKey("key1", &privateKey1.PublicKey, privateKey1)
	if err != nil {
		t.Fatalf("failed to register first key: %v", err)
	}

	err = vf.RegisterKey("key2", &privateKey2.PublicKey, privateKey1)
	if err != nil {
		t.Fatalf("failed to register second key: %v", err)
	}

	// Add a secret
	secretName := "testsecret"
	secretValue := "SECRET_VALUE_12345"
	err = vf.AddSecretUTF8(secretName, secretValue)
	if err != nil {
		t.Fatalf("failed to add secret: %v", err)
	}

	// Deregister the first key
	err = vf.DeregisterKey("key1")
	if err != nil {
		t.Fatalf("failed to deregister key: %v", err)
	}

	// First key should no longer be able to read the secret
	_, err = vf.ReadSecret(secretName, privateKey1)
	if err == nil {
		t.Fatal("expected error when reading secret with deregistered key")
	}

	// Second key should still work
	recoveredSecret, err := vf.ReadSecret(secretName, privateKey2)
	if err != nil {
		t.Fatalf("failed to read secret with remaining key: %v", err)
	}

	if recoveredSecret != secretValue {
		t.Fatalf("recovered secret doesn't match: got %q, want %q", recoveredSecret, secretValue)
	}
}

func TestDeregisterLastKey(t *testing.T) {
	privateKey, err := crypto.GenerateRSAKey(crypto.RSAKeySize)
	if err != nil {
		t.Fatalf("failed to generate test key: %v", err)
	}

	vf := NewVaultfile()
	err = vf.RegisterKey("onlykey", &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatalf("failed to register key: %v", err)
	}

	// Try to deregister the only key
	err = vf.DeregisterKey("onlykey")
	if err == nil {
		t.Fatal("expected error when deregistering the last key")
	}

	vaultErr, ok := err.(*VaultfileError)
	if !ok {
		t.Fatalf("expected VaultfileError, got %T", err)
	}

	if vaultErr.Kind != VaultfileMustHaveKeys {
		t.Fatalf("expected VaultfileMustHaveKeys error, got %v", vaultErr.Kind)
	}
}

func TestSecretOperations(t *testing.T) {
	privateKey, err := crypto.GenerateRSAKey(crypto.RSAKeySize)
	if err != nil {
		t.Fatalf("failed to generate test key: %v", err)
	}

	vf := NewVaultfile()
	err = vf.RegisterKey("testkey", &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatalf("failed to register key: %v", err)
	}

	// Test HasSecretNamed before adding any secrets
	if vf.HasSecretNamed("nonexistent") {
		t.Fatal("HasSecretNamed returned true for nonexistent secret")
	}

	// Add a secret
	secretName := "testsecret"
	secretValue := "SECRET_VALUE_12345"
	err = vf.AddSecretUTF8(secretName, secretValue)
	if err != nil {
		t.Fatalf("failed to add secret: %v", err)
	}

	// Test HasSecretNamed after adding secret
	if !vf.HasSecretNamed(secretName) {
		t.Fatal("HasSecretNamed returned false for existing secret")
	}

	// Test ListSecrets
	secrets := vf.ListSecrets()
	if len(secrets) != 1 || secrets[0] != secretName {
		t.Fatalf("ListSecrets returned unexpected result: got %v, want [%s]", secrets, secretName)
	}

	// Delete the secret
	err = vf.DeleteSecret(secretName)
	if err != nil {
		t.Fatalf("failed to delete secret: %v", err)
	}

	// Verify it's gone
	if vf.HasSecretNamed(secretName) {
		t.Fatal("HasSecretNamed returned true for deleted secret")
	}

	secrets = vf.ListSecrets()
	if len(secrets) != 0 {
		t.Fatalf("ListSecrets returned unexpected result after deletion: got %v, want []", secrets)
	}
}

func TestDeleteNonexistentSecret(t *testing.T) {
	privateKey, err := crypto.GenerateRSAKey(crypto.RSAKeySize)
	if err != nil {
		t.Fatalf("failed to generate test key: %v", err)
	}

	vf := NewVaultfile()
	err = vf.RegisterKey("testkey", &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatalf("failed to register key: %v", err)
	}

	err = vf.DeleteSecret("nonexistent")
	if err == nil {
		t.Fatal("expected error when deleting nonexistent secret")
	}

	vaultErr, ok := err.(*VaultfileError)
	if !ok {
		t.Fatalf("expected VaultfileError, got %T", err)
	}

	if vaultErr.Kind != SecretNotFound {
		t.Fatalf("expected SecretNotFound error, got %v", vaultErr.Kind)
	}
}
