package vault

import (
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"jemmic.com/vaultfile-go/internal/crypto"
)

// VaultfileSecret represents a secret stored in the vaultfile
type VaultfileSecret struct {
	Secret       string            `json:"secret"`
	EncryptedKey map[string]string `json:"encrypted_key"`
}

// Vaultfile represents the main vault data structure
type Vaultfile struct {
	Keys    map[string]*rsa.PublicKey   `json:"keys"`
	Secrets map[string]*VaultfileSecret `json:"secrets"`
}

// VaultfileError represents errors that can occur during vault operations
type VaultfileError struct {
	Kind VaultfileErrorKind
	Msg  string
}

// VaultfileErrorKind represents the type of vault error
type VaultfileErrorKind int

const (
	VaultfileNotFound VaultfileErrorKind = iota
	InvalidJSON
	VaultfileMustHaveKeys
	SecretNotSharedWithAllRegisteredKeys
	PrivateKeyNotFound
	PrivateKeyNotRegistered
	VaultfileKeyNotRegistered
	SecretNotFound
	CorruptDataInSecret
	BadBase64Secret
	EncryptionError
	IOError
)

func (e *VaultfileError) Error() string {
	return e.Msg
}

// NewVaultfile creates a new empty vaultfile
func NewVaultfile() *Vaultfile {
	return &Vaultfile{
		Keys:    make(map[string]*rsa.PublicKey),
		Secrets: make(map[string]*VaultfileSecret),
	}
}

// LoadFromFile loads a vaultfile from the specified path
func LoadFromFile(vaultfilePath string) (*Vaultfile, error) {
	if _, err := os.Stat(vaultfilePath); os.IsNotExist(err) {
		return nil, &VaultfileError{
			Kind: VaultfileNotFound,
			Msg:  fmt.Sprintf("vaultfile not found at %s", vaultfilePath),
		}
	}

	data, err := os.ReadFile(vaultfilePath)
	if err != nil {
		return nil, &VaultfileError{
			Kind: IOError,
			Msg:  fmt.Sprintf("failed to read vaultfile: %v", err),
		}
	}

	var vf Vaultfile
	if err := json.Unmarshal(data, &vf); err != nil {
		return nil, &VaultfileError{
			Kind: InvalidJSON,
			Msg:  fmt.Sprintf("failed to parse vaultfile JSON: %v", err),
		}
	}

	if err := vf.validate(); err != nil {
		return nil, err
	}

	return &vf, nil
}

// validate ensures the vaultfile is in a valid state
func (vf *Vaultfile) validate() error {
	if len(vf.Keys) == 0 {
		return &VaultfileError{
			Kind: VaultfileMustHaveKeys,
			Msg:  "vaultfile must have at least one registered key",
		}
	}

	// Ensure all registered keys can access all secrets
	for keyName := range vf.Keys {
		for secretName, secret := range vf.Secrets {
			if _, exists := secret.EncryptedKey[keyName]; !exists {
				return &VaultfileError{
					Kind: SecretNotSharedWithAllRegisteredKeys,
					Msg:  fmt.Sprintf("secret %s is not shared with key %s", secretName, keyName),
				}
			}
		}
	}

	return nil
}

// GenerateAndSaveKey generates a new RSA key pair and saves it to the specified path
func GenerateAndSaveKey(privateKeyPath string) error {
	publicKeyPath := privateKeyPath + ".pub"

	// Generate RSA key pair
	privateKey, err := crypto.GenerateRSAKey(crypto.RSAKeySize)
	if err != nil {
		return fmt.Errorf("failed to generate RSA key: %w", err)
	}

	// Marshal private key to JSON
	privateKeyData, err := json.Marshal(privateKey)
	if err != nil {
		return fmt.Errorf("failed to marshal private key: %w", err)
	}

	// Marshal public key to JSON
	publicKeyData, err := json.Marshal(&privateKey.PublicKey)
	if err != nil {
		return fmt.Errorf("failed to marshal public key: %w", err)
	}

	// Ensure directory exists
	dir := filepath.Dir(privateKeyPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create directory: %w", err)
	}

	// Write private key
	if err := os.WriteFile(privateKeyPath, privateKeyData, 0600); err != nil {
		return fmt.Errorf("failed to write private key: %w", err)
	}

	// Write public key
	if err := os.WriteFile(publicKeyPath, publicKeyData, 0644); err != nil {
		return fmt.Errorf("failed to write public key: %w", err)
	}

	return nil
}

// LoadPrivateKey loads a private key from the specified path
func LoadPrivateKey(privateKeyPath string) (*rsa.PrivateKey, error) {
	if _, err := os.Stat(privateKeyPath); os.IsNotExist(err) {
		return nil, &VaultfileError{
			Kind: PrivateKeyNotFound,
			Msg:  fmt.Sprintf("private key not found at %s", privateKeyPath),
		}
	}

	data, err := os.ReadFile(privateKeyPath)
	if err != nil {
		return nil, &VaultfileError{
			Kind: IOError,
			Msg:  fmt.Sprintf("failed to read private key: %v", err),
		}
	}

	var privateKey rsa.PrivateKey
	if err := json.Unmarshal(data, &privateKey); err != nil {
		return nil, &VaultfileError{
			Kind: InvalidJSON,
			Msg:  fmt.Sprintf("failed to parse private key JSON: %v", err),
		}
	}

	return &privateKey, nil
}

// LoadPublicKey loads a public key from the specified path
func LoadPublicKey(publicKeyPath string) (*rsa.PublicKey, error) {
	data, err := os.ReadFile(publicKeyPath)
	if err != nil {
		return nil, &VaultfileError{
			Kind: IOError,
			Msg:  fmt.Sprintf("failed to read public key: %v", err),
		}
	}

	var publicKey rsa.PublicKey
	if err := json.Unmarshal(data, &publicKey); err != nil {
		return nil, &VaultfileError{
			Kind: InvalidJSON,
			Msg:  fmt.Sprintf("failed to parse public key JSON: %v", err),
		}
	}

	return &publicKey, nil
}

// ParsePublicKey parses a public key from a JSON string
func ParsePublicKey(publicKeyJSON string) (*rsa.PublicKey, error) {
	var publicKey rsa.PublicKey
	if err := json.Unmarshal([]byte(publicKeyJSON), &publicKey); err != nil {
		return nil, &VaultfileError{
			Kind: InvalidJSON,
			Msg:  fmt.Sprintf("failed to parse public key JSON: %v", err),
		}
	}

	return &publicKey, nil
}

// PublicKeyToJSON converts a public key to JSON string
func PublicKeyToJSON(publicKey *rsa.PublicKey) (string, error) {
	data, err := json.Marshal(publicKey)
	if err != nil {
		return "", fmt.Errorf("failed to marshal public key: %w", err)
	}
	return string(data), nil
}

// FindRegisteredNameOfKey finds the name of a registered key
func (vf *Vaultfile) FindRegisteredNameOfKey(key *rsa.PublicKey) string {
	for keyName, registeredKey := range vf.Keys {
		if registeredKey.N.Cmp(key.N) == 0 && registeredKey.E == key.E {
			return keyName
		}
	}
	return ""
}

// IsKeyRegistered checks if a key is registered with the given name
func (vf *Vaultfile) IsKeyRegistered(keyName string) bool {
	_, exists := vf.Keys[keyName]
	return exists
}

// GetKey retrieves a public key by name
func (vf *Vaultfile) GetKey(keyName string) (*rsa.PublicKey, bool) {
	key, exists := vf.Keys[keyName]
	return key, exists
}

// RegisterKey registers a new key in the vaultfile
func (vf *Vaultfile) RegisterKey(keyName string, newKey *rsa.PublicKey, alreadyRegisteredPrivateKey *rsa.PrivateKey) error {
	if len(vf.Secrets) > 0 {
		// Find the private key name
		privateKeyName := vf.FindRegisteredNameOfKey(&alreadyRegisteredPrivateKey.PublicKey)
		if privateKeyName == "" {
			return &VaultfileError{
				Kind: PrivateKeyNotRegistered,
				Msg:  "the private key is not registered in the vaultfile",
			}
		}

		// Grant access to all secrets for the new key
		for secretName, secret := range vf.Secrets {
			encryptedKeyStr, exists := secret.EncryptedKey[privateKeyName]
			if !exists {
				return &VaultfileError{
					Kind: SecretNotSharedWithAllRegisteredKeys,
					Msg:  fmt.Sprintf("secret %s is not shared with key %s", secretName, privateKeyName),
				}
			}

			// Decrypt the AES key
			rawEncryptedKey, err := base64.StdEncoding.DecodeString(encryptedKeyStr)
			if err != nil {
				return &VaultfileError{
					Kind: BadBase64Secret,
					Msg:  fmt.Sprintf("failed to decode encrypted key: %v", err),
				}
			}

			rawAESKey, err := crypto.DecryptRSAOAEP(alreadyRegisteredPrivateKey, rawEncryptedKey)
			if err != nil {
				return &VaultfileError{
					Kind: EncryptionError,
					Msg:  fmt.Sprintf("failed to decrypt AES key: %v", err),
				}
			}

			// Encrypt the AES key with the new public key
			newEncrypted, err := crypto.EncryptRSAOAEP(newKey, rawAESKey)
			if err != nil {
				return &VaultfileError{
					Kind: EncryptionError,
					Msg:  fmt.Sprintf("failed to encrypt AES key: %v", err),
				}
			}

			base64EncryptedKey := base64.StdEncoding.EncodeToString(newEncrypted)
			secret.EncryptedKey[keyName] = base64EncryptedKey
		}
	}

	vf.Keys[keyName] = newKey
	return nil
}

// DeregisterKey removes a key from the vaultfile
func (vf *Vaultfile) DeregisterKey(keyName string) error {
	if len(vf.Keys) == 1 {
		return &VaultfileError{
			Kind: VaultfileMustHaveKeys,
			Msg:  "vaultfile must have at least one key",
		}
	}

	if _, exists := vf.Keys[keyName]; !exists {
		return &VaultfileError{
			Kind: VaultfileKeyNotRegistered,
			Msg:  fmt.Sprintf("key %s is not registered", keyName),
		}
	}

	// Remove the key from all secrets
	for _, secret := range vf.Secrets {
		delete(secret.EncryptedKey, keyName)
	}

	delete(vf.Keys, keyName)
	return nil
}

// ListKeys returns a list of all registered key names
func (vf *Vaultfile) ListKeys() []string {
	keys := make([]string, 0, len(vf.Keys))
	for keyName := range vf.Keys {
		keys = append(keys, keyName)
	}
	return keys
}

// ListSecrets returns a list of all secret names
func (vf *Vaultfile) ListSecrets() []string {
	secrets := make([]string, 0, len(vf.Secrets))
	for secretName := range vf.Secrets {
		secrets = append(secrets, secretName)
	}
	return secrets
}

// HasSecretNamed checks if a secret with the given name exists
func (vf *Vaultfile) HasSecretNamed(secretName string) bool {
	_, exists := vf.Secrets[secretName]
	return exists
}

// AddSecretUTF8 adds a UTF-8 string secret to the vaultfile
func (vf *Vaultfile) AddSecretUTF8(secretName, secretValue string) error {
	encryptedSecret, err := crypto.EncryptSecretUTF8(secretValue)
	if err != nil {
		return fmt.Errorf("failed to encrypt secret: %w", err)
	}

	return vf.addEncryptedSecret(secretName, encryptedSecret)
}

// AddSecretBase64 adds a base64-encoded secret to the vaultfile
func (vf *Vaultfile) AddSecretBase64(secretName, secretValueBase64 string) error {
	encryptedSecret, err := crypto.EncryptSecretBase64(secretValueBase64)
	if err != nil {
		return fmt.Errorf("failed to encrypt secret: %w", err)
	}

	return vf.addEncryptedSecret(secretName, encryptedSecret)
}

// addEncryptedSecret adds an encrypted secret to the vaultfile
func (vf *Vaultfile) addEncryptedSecret(secretName string, encryptedSecret *crypto.EncryptionResult) error {
	encryptedKey := make(map[string]string)

	// Encrypt the AES key with each registered public key
	for keyName, rsaKey := range vf.Keys {
		aesKeyCiphertext, err := crypto.EncryptRSAOAEP(rsaKey, encryptedSecret.AESKey)
		if err != nil {
			return &VaultfileError{
				Kind: EncryptionError,
				Msg:  fmt.Sprintf("failed to encrypt AES key: %v", err),
			}
		}

		aesKeyCiphertextBase64 := base64.StdEncoding.EncodeToString(aesKeyCiphertext)
		encryptedKey[keyName] = aesKeyCiphertextBase64
	}

	vf.Secrets[secretName] = &VaultfileSecret{
		Secret:       encryptedSecret.EncryptedData,
		EncryptedKey: encryptedKey,
	}

	return nil
}

// ReadSecret reads and decrypts a secret from the vaultfile
func (vf *Vaultfile) ReadSecret(secretName string, privateKey *rsa.PrivateKey) (string, error) {
	keyName := vf.FindRegisteredNameOfKey(&privateKey.PublicKey)
	if keyName == "" {
		return "", &VaultfileError{
			Kind: PrivateKeyNotRegistered,
			Msg:  "the private key is not registered in the vaultfile",
		}
	}

	secret, exists := vf.Secrets[secretName]
	if !exists {
		return "", &VaultfileError{
			Kind: SecretNotFound,
			Msg:  fmt.Sprintf("secret %s not found", secretName),
		}
	}

	base64AESKey, exists := secret.EncryptedKey[keyName]
	if !exists {
		return "", &VaultfileError{
			Kind: SecretNotSharedWithAllRegisteredKeys,
			Msg:  fmt.Sprintf("secret %s is not shared with key %s", secretName, keyName),
		}
	}

	// Decrypt the AES key
	rsaEncryptedAESKey, err := base64.StdEncoding.DecodeString(base64AESKey)
	if err != nil {
		return "", &VaultfileError{
			Kind: BadBase64Secret,
			Msg:  fmt.Sprintf("failed to decode encrypted AES key: %v", err),
		}
	}

	aesKey, err := crypto.DecryptRSAOAEP(privateKey, rsaEncryptedAESKey)
	if err != nil {
		return "", &VaultfileError{
			Kind: EncryptionError,
			Msg:  fmt.Sprintf("failed to decrypt AES key: %v", err),
		}
	}

	// Decrypt the secret
	return crypto.DecryptSecret(secret.Secret, aesKey)
}

// DeleteSecret removes a secret from the vaultfile
func (vf *Vaultfile) DeleteSecret(secretName string) error {
	if !vf.HasSecretNamed(secretName) {
		return &VaultfileError{
			Kind: SecretNotFound,
			Msg:  fmt.Sprintf("secret %s not found", secretName),
		}
	}

	delete(vf.Secrets, secretName)
	return nil
}

// SaveToFile saves the vaultfile to the specified path
func (vf *Vaultfile) SaveToFile(vaultfilePath string) error {
	// Create a temporary structure for JSON marshaling
	type jsonVaultfile struct {
		Keys    map[string]interface{}      `json:"keys"`
		Secrets map[string]*VaultfileSecret `json:"secrets"`
	}

	jsonVF := jsonVaultfile{
		Keys:    make(map[string]interface{}),
		Secrets: vf.Secrets,
	}

	// Convert RSA public keys to JSON-serializable format
	for keyName, key := range vf.Keys {
		jsonVF.Keys[keyName] = key
	}

	data, err := json.MarshalIndent(jsonVF, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal vaultfile: %w", err)
	}

	// Format the JSON to put keys on one line (similar to Rust implementation)
	formattedData := vf.moveKeysIntoOneLine(string(data))

	// Ensure directory exists
	dir := filepath.Dir(vaultfilePath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create directory: %w", err)
	}

	if err := os.WriteFile(vaultfilePath, []byte(formattedData), 0644); err != nil {
		return fmt.Errorf("failed to write vaultfile: %w", err)
	}

	return nil
}

// moveKeysIntoOneLine formats the JSON to put keys on one line
func (vf *Vaultfile) moveKeysIntoOneLine(uglyVaultfile string) string {
	lines := strings.Split(uglyVaultfile, "\n")
	var prettyLines []string
	var currentLine strings.Builder
	insideKeys := false
	keysFound := false
	bracesLevel := 0

	for _, line := range lines {
		trimmedLine := strings.TrimSpace(line)
		if currentLine.Len() == 0 {
			currentLine.WriteString(line)
		} else {
			currentLine.WriteString(strings.ReplaceAll(trimmedLine, " ", ""))
		}

		if insideKeys {
			if strings.Contains(line, "{") {
				bracesLevel++
			}
			if strings.Contains(line, "}") {
				bracesLevel--
			}
			if bracesLevel < 0 {
				insideKeys = false
			}
		}

		if !insideKeys || bracesLevel == 0 {
			prettyLines = append(prettyLines, currentLine.String())
			currentLine.Reset()
		}

		if !keysFound && strings.HasSuffix(line, "\"keys\": {") {
			insideKeys = true
			keysFound = true
		}
	}

	return strings.Join(prettyLines, "\n")
}

// GetHomeDirectory returns the user's home directory
func GetHomeDirectory() (string, error) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("failed to get home directory: %w", err)
	}
	return homeDir, nil
}

// GetDefaultVaultfileFolder returns the default vaultfile configuration folder
func GetDefaultVaultfileFolder() (string, error) {
	homeDir, err := GetHomeDirectory()
	if err != nil {
		return "", err
	}

	// Check XDG_CONFIG_HOME
	if xdgConfigHome := os.Getenv("XDG_CONFIG_HOME"); xdgConfigHome != "" {
		return filepath.Join(xdgConfigHome, "vaultfile"), nil
	}

	return filepath.Join(homeDir, ".config", "vaultfile"), nil
}

// EnsureFolderExists creates a directory if it doesn't exist
func EnsureFolderExists(folderPath string) error {
	if info, err := os.Stat(folderPath); err == nil {
		if !info.IsDir() {
			return fmt.Errorf("path %s exists but is not a directory", folderPath)
		}
		return nil
	}

	if err := os.MkdirAll(folderPath, 0755); err != nil {
		return fmt.Errorf("failed to create directory %s: %w", folderPath, err)
	}

	return nil
}

// LoadOrCreateVaultfile loads a vaultfile or creates a new one if it doesn't exist
func LoadOrCreateVaultfile(vaultfilePath string) (*Vaultfile, error) {
	vf, err := LoadFromFile(vaultfilePath)
	if err != nil {
		if vaultErr, ok := err.(*VaultfileError); ok && vaultErr.Kind == VaultfileNotFound {
			return NewVaultfile(), nil
		}
		return nil, err
	}
	return vf, nil
}

// CheckFileOverwrite checks if a file exists and prompts for overwrite confirmation
func CheckFileOverwrite(filePath string, overwriteNo bool) error {
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		return nil
	}

	if overwriteNo {
		return fmt.Errorf("file at '%s' already exists, and no overwriting has been selected", filePath)
	}

	// In a real CLI application, you would prompt the user here
	// For now, we'll just return an error
	return fmt.Errorf("file at '%s' already exists", filePath)
}

// WriteToFile writes content to a file, optionally overwriting
func WriteToFile(filePath string, content []byte, overwrite bool) error {
	if !overwrite {
		if _, err := os.Stat(filePath); err == nil {
			return fmt.Errorf("file %s already exists", filePath)
		}
	}

	// Ensure directory exists
	dir := filepath.Dir(filePath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create directory: %w", err)
	}

	if err := os.WriteFile(filePath, content, 0644); err != nil {
		return fmt.Errorf("failed to write file: %w", err)
	}

	return nil
}
