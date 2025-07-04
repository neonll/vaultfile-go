package main

import (
	"crypto/rsa"
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"neonll.com/vaultfile-go/pkg/vault"
)

var (
	vaultfilePath  string
	keyName        string
	keyFile        string
	keyJSON        string
	privateKeyName string
	secretName     string
	secretValue    string
	secretBase64   string
	overwriteYes   bool
	overwriteNo    bool
	noEOL          bool
)

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

var rootCmd = &cobra.Command{
	Use:   "vaultfile",
	Short: "A basic shared secret manager",
	Long: `vaultfile is a secure shared secret manager that uses asymmetric cryptography
to allow multiple users to securely share secrets without requiring a server.`,
}

func init() {
	// Get username for defaults
	username := getUsername()
	defaultVaultfilePath := "Vaultfile"

	// Get default paths
	defaultVaultfileFolder, err := vault.GetDefaultVaultfileFolder()
	if err != nil {
		defaultVaultfileFolder = filepath.Join(os.Getenv("HOME"), ".config", "vaultfile")
	}
	defaultKeyFile := filepath.Join(defaultVaultfileFolder, username+".key.pub")

	// Add all subcommands
	rootCmd.AddCommand(generateKeyCmd)
	rootCmd.AddCommand(registerKeyCmd)
	rootCmd.AddCommand(listKeysCmd)
	rootCmd.AddCommand(listSecretsCmd)
	rootCmd.AddCommand(showKeyCmd)
	rootCmd.AddCommand(deregisterKeyCmd)
	rootCmd.AddCommand(addSecretCmd)
	rootCmd.AddCommand(readSecretCmd)
	rootCmd.AddCommand(deleteSecretCmd)

	// Generate key command
	generateKeyCmd.Flags().StringVar(&keyFile, "key-path", defaultVaultfileFolder, "Path to place the generated public/private keypair in")
	generateKeyCmd.Flags().BoolVarP(&overwriteYes, "yes", "y", false, "Overwrite the key file if it already exists")
	generateKeyCmd.Flags().BoolVar(&overwriteNo, "no", false, "Do not overwrite the key file if it already exists")

	// Register key command
	registerKeyCmd.Flags().StringVarP(&vaultfilePath, "file", "f", defaultVaultfilePath, "The vaultfile to register the key in")
	registerKeyCmd.Flags().StringVar(&keyName, "key-name", username, "The name to register the key under")
	registerKeyCmd.Flags().StringVar(&keyFile, "key-file", defaultKeyFile, "The file containing the public key")
	registerKeyCmd.Flags().StringVar(&keyJSON, "key-json", "", "A JSON string containing the public key")
	registerKeyCmd.Flags().StringVar(&privateKeyName, "private-key-name", username, "The name of the private key to use")
	registerKeyCmd.Flags().BoolVarP(&overwriteYes, "yes", "y", false, "Overwrite the key if it already exists")
	registerKeyCmd.Flags().BoolVar(&overwriteNo, "no", false, "Do not overwrite the key if it already exists")
	registerKeyCmd.MarkFlagRequired("key-name")

	// List keys command
	listKeysCmd.Flags().StringVarP(&vaultfilePath, "file", "f", defaultVaultfilePath, "The path of the vaultfile to use")

	// List secrets command
	listSecretsCmd.Flags().StringVarP(&vaultfilePath, "file", "f", defaultVaultfilePath, "The path of the vaultfile to use")

	// Show key command
	showKeyCmd.Flags().StringVarP(&vaultfilePath, "file", "f", defaultVaultfilePath, "The path of the vaultfile to use")
	showKeyCmd.Flags().StringVar(&keyName, "key-name", "", "The name of the key to show")
	showKeyCmd.MarkFlagRequired("key-name")

	// Deregister key command
	deregisterKeyCmd.Flags().StringVarP(&vaultfilePath, "file", "f", "", "The path of the vaultfile to use")
	deregisterKeyCmd.Flags().StringVar(&keyName, "key-name", "", "The name of the key to remove")
	deregisterKeyCmd.MarkFlagRequired("file")
	deregisterKeyCmd.MarkFlagRequired("key-name")

	// Add secret command
	addSecretCmd.Flags().StringVarP(&vaultfilePath, "file", "f", "", "The path of the vaultfile to store the secret in")
	addSecretCmd.Flags().StringVarP(&secretName, "name", "n", "", "The name under which to store the secret")
	addSecretCmd.Flags().StringVarP(&secretValue, "value", "v", "", "The secret value to store")
	addSecretCmd.Flags().StringVar(&secretBase64, "base64-value", "", "The secret value as base64")
	addSecretCmd.Flags().BoolVarP(&overwriteYes, "yes", "y", false, "Overwrite the secret if it already exists")
	addSecretCmd.Flags().BoolVar(&overwriteNo, "no", false, "Do not overwrite the secret if it already exists")
	addSecretCmd.MarkFlagRequired("file")
	addSecretCmd.MarkFlagRequired("name")

	// Read secret command
	readSecretCmd.Flags().StringVarP(&vaultfilePath, "file", "f", "", "The path of the vaultfile to read from")
	readSecretCmd.Flags().StringVar(&secretName, "name", "", "The name of the secret to read")
	readSecretCmd.Flags().StringVarP(&keyName, "key-name", "k", username, "The name of the private key to use")
	readSecretCmd.Flags().StringVar(&keyFile, "key-file", "", "A file containing a private key")
	readSecretCmd.Flags().BoolVar(&noEOL, "no-eol", false, "Do not print an end-of-line character")
	readSecretCmd.MarkFlagRequired("file")
	readSecretCmd.MarkFlagRequired("name")

	// Delete secret command
	deleteSecretCmd.Flags().StringVarP(&vaultfilePath, "file", "f", "", "The vaultfile to delete the secret from")
	deleteSecretCmd.Flags().StringVar(&secretName, "name", "", "The name of the secret to delete")
	deleteSecretCmd.MarkFlagRequired("file")
	deleteSecretCmd.MarkFlagRequired("name")
}

var generateKeyCmd = &cobra.Command{
	Use:   "generate-key",
	Short: "Generate a new private key",
	RunE: func(cmd *cobra.Command, args []string) error {
		return generateKeyCommand()
	},
}

var registerKeyCmd = &cobra.Command{
	Use:     "register-key",
	Aliases: []string{"new"},
	Short:   "Register a key in a vaultfile",
	RunE: func(cmd *cobra.Command, args []string) error {
		return registerKeyCommand()
	},
}

var listKeysCmd = &cobra.Command{
	Use:   "list-keys",
	Short: "List all the keys registered in the vaultfile",
	RunE: func(cmd *cobra.Command, args []string) error {
		return listKeysCommand()
	},
}

var listSecretsCmd = &cobra.Command{
	Use:   "list-secrets",
	Short: "List all the secrets registered in the vaultfile",
	RunE: func(cmd *cobra.Command, args []string) error {
		return listSecretsCommand()
	},
}

var showKeyCmd = &cobra.Command{
	Use:   "show-key",
	Short: "Show the JSON-encoded public key",
	RunE: func(cmd *cobra.Command, args []string) error {
		return showKeyCommand()
	},
}

var deregisterKeyCmd = &cobra.Command{
	Use:   "deregister-key",
	Short: "Remove a registered public key from the vaultfile",
	RunE: func(cmd *cobra.Command, args []string) error {
		return deregisterKeyCommand()
	},
}

var addSecretCmd = &cobra.Command{
	Use:   "add-secret",
	Short: "Add a secret to the vaultfile",
	RunE: func(cmd *cobra.Command, args []string) error {
		return addSecretCommand()
	},
}

var readSecretCmd = &cobra.Command{
	Use:   "read-secret",
	Short: "Read a secret saved in the vaultfile",
	RunE: func(cmd *cobra.Command, args []string) error {
		return readSecretCommand()
	},
}

var deleteSecretCmd = &cobra.Command{
	Use:   "delete-secret",
	Short: "Delete a secret from the specified vaultfile",
	RunE: func(cmd *cobra.Command, args []string) error {
		return deleteSecretCommand()
	},
}

func generateKeyCommand() error {
	username := getUsername()

	// Build key path
	var keyPath string
	if keyFile != "" {
		if info, err := os.Stat(keyFile); err == nil && info.IsDir() {
			keyPath = filepath.Join(keyFile, username+".key")
		} else {
			keyPath = keyFile
		}
	} else {
		defaultFolder, err := vault.GetDefaultVaultfileFolder()
		if err != nil {
			return fmt.Errorf("failed to get default vaultfile folder: %w", err)
		}
		keyPath = filepath.Join(defaultFolder, username+".key")
	}

	// Ensure folder exists
	if err := vault.EnsureFolderExists(filepath.Dir(keyPath)); err != nil {
		return fmt.Errorf("failed to create directory: %w", err)
	}

	// Check file overwrite
	if !overwriteYes {
		if err := vault.CheckFileOverwrite(keyPath, overwriteNo); err != nil {
			return err
		}
	}

	// Generate and save key
	if err := vault.GenerateAndSaveKey(keyPath); err != nil {
		return fmt.Errorf("failed to generate key: %w", err)
	}

	fmt.Println("The private key has been generated and saved.")
	fmt.Printf("It is up to you to ensure that the private key at %s, stays private!\n", keyPath)
	fmt.Println("It is recommended that you make it accessible only for you, with the following command:")
	fmt.Printf("$ chmod 600 %s\n", keyPath)
	fmt.Println("It would be even better if you made it read-only (to prevent accidental deletion), with:")
	fmt.Printf("$ chmod 400 %s\n", keyPath)

	return nil
}

func registerKeyCommand() error {
	// Load or parse the public key
	var newKey *rsa.PublicKey
	var err error

	if keyJSON != "" {
		newKey, err = vault.ParsePublicKey(keyJSON)
	} else if keyFile != "" {
		newKey, err = vault.LoadPublicKey(keyFile)
	} else {
		return fmt.Errorf("either --key-json or --key-file must be specified")
	}

	if err != nil {
		return fmt.Errorf("failed to load public key: %w", err)
	}

	// Load private key
	defaultFolder, err := vault.GetDefaultVaultfileFolder()
	if err != nil {
		return fmt.Errorf("failed to get default vaultfile folder: %w", err)
	}

	privateKeyPath := filepath.Join(defaultFolder, privateKeyName+".key")
	privateKey, err := vault.LoadPrivateKey(privateKeyPath)
	if err != nil {
		return fmt.Errorf("failed to load private key: %w", err)
	}

	// Load or create vaultfile
	vf, err := vault.LoadOrCreateVaultfile(vaultfilePath)
	if err != nil {
		return fmt.Errorf("failed to load vaultfile: %w", err)
	}

	// Check for key collision
	if !overwriteYes && vf.IsKeyRegistered(keyName) {
		if overwriteNo {
			fmt.Printf("The vaultfile at '%s' already has a key registered under name %s, and no overwriting has been selected. Doing nothing...\n", vaultfilePath, keyName)
			return nil
		}
		return fmt.Errorf("vaultfile already has a key registered under name %s", keyName)
	}

	// Register the key
	if err := vf.RegisterKey(keyName, newKey, privateKey); err != nil {
		return fmt.Errorf("failed to register key: %w", err)
	}

	// Save the vaultfile
	if err := vf.SaveToFile(vaultfilePath); err != nil {
		return fmt.Errorf("failed to save vaultfile: %w", err)
	}

	fmt.Printf("New key registered in vaultfile at %s under name %s.\n", vaultfilePath, keyName)
	return nil
}

func listKeysCommand() error {
	vf, err := vault.LoadFromFile(vaultfilePath)
	if err != nil {
		return fmt.Errorf("failed to load vaultfile: %w", err)
	}

	keys := vf.ListKeys()
	for _, key := range keys {
		fmt.Println(key)
	}

	return nil
}

func listSecretsCommand() error {
	vf, err := vault.LoadFromFile(vaultfilePath)
	if err != nil {
		return fmt.Errorf("failed to load vaultfile: %w", err)
	}

	secrets := vf.ListSecrets()
	for _, secret := range secrets {
		fmt.Println(secret)
	}

	return nil
}

func showKeyCommand() error {
	vf, err := vault.LoadFromFile(vaultfilePath)
	if err != nil {
		return fmt.Errorf("failed to load vaultfile: %w", err)
	}

	key, exists := vf.GetKey(keyName)
	if !exists {
		return fmt.Errorf("no key named '%s' was found in the vaultfile at %s", keyName, vaultfilePath)
	}

	keyJSON, err := vault.PublicKeyToJSON(key)
	if err != nil {
		return fmt.Errorf("failed to convert key to JSON: %w", err)
	}

	fmt.Println(keyJSON)
	return nil
}

func deregisterKeyCommand() error {
	vf, err := vault.LoadFromFile(vaultfilePath)
	if err != nil {
		return fmt.Errorf("failed to load vaultfile: %w", err)
	}

	if err := vf.DeregisterKey(keyName); err != nil {
		return fmt.Errorf("failed to deregister key: %w", err)
	}

	if err := vf.SaveToFile(vaultfilePath); err != nil {
		return fmt.Errorf("failed to save vaultfile: %w", err)
	}

	fmt.Printf("Key '%s' has been deregistered from vaultfile at %s.\n", keyName, vaultfilePath)
	return nil
}

func addSecretCommand() error {
	if secretValue == "" && secretBase64 == "" {
		return fmt.Errorf("either --value or --base64-value must be provided")
	}

	if secretValue != "" && secretBase64 != "" {
		return fmt.Errorf("only one of --value or --base64-value may be provided")
	}

	vf, err := vault.LoadFromFile(vaultfilePath)
	if err != nil {
		return fmt.Errorf("failed to load vaultfile: %w", err)
	}

	// Check for secret collision
	if !overwriteYes && vf.HasSecretNamed(secretName) {
		if overwriteNo {
			fmt.Printf("The vaultfile at '%s' already has a secret registered under name %s, and no overwriting has been selected. Doing nothing...\n", vaultfilePath, secretName)
			return nil
		}
		return fmt.Errorf("vaultfile already has a secret registered under name %s", secretName)
	}

	// Add the secret
	if secretValue != "" {
		err = vf.AddSecretUTF8(secretName, secretValue)
	} else {
		err = vf.AddSecretBase64(secretName, secretBase64)
	}

	if err != nil {
		return fmt.Errorf("failed to add secret: %w", err)
	}

	// Save the vaultfile
	if err := vf.SaveToFile(vaultfilePath); err != nil {
		return fmt.Errorf("failed to save vaultfile: %w", err)
	}

	fmt.Printf("Secret '%s' has been added to vaultfile at %s.\n", secretName, vaultfilePath)
	return nil
}

func readSecretCommand() error {
	// Determine private key path
	var privateKeyPath string
	if keyFile != "" {
		privateKeyPath = keyFile
	} else {
		defaultFolder, err := vault.GetDefaultVaultfileFolder()
		if err != nil {
			return fmt.Errorf("failed to get default vaultfile folder: %w", err)
		}
		privateKeyPath = filepath.Join(defaultFolder, keyName+".key")
	}

	// Load private key
	privateKey, err := vault.LoadPrivateKey(privateKeyPath)
	if err != nil {
		return fmt.Errorf("failed to load private key: %w", err)
	}

	// Load vaultfile
	vf, err := vault.LoadFromFile(vaultfilePath)
	if err != nil {
		return fmt.Errorf("failed to load vaultfile: %w", err)
	}

	// Read secret
	secretValue, err := vf.ReadSecret(secretName, privateKey)
	if err != nil {
		return fmt.Errorf("failed to read secret: %w", err)
	}

	// Print secret
	if noEOL {
		fmt.Print(secretValue)
	} else {
		fmt.Println(secretValue)
	}

	return nil
}

func deleteSecretCommand() error {
	vf, err := vault.LoadFromFile(vaultfilePath)
	if err != nil {
		return fmt.Errorf("failed to load vaultfile: %w", err)
	}

	if err := vf.DeleteSecret(secretName); err != nil {
		return fmt.Errorf("failed to delete secret: %w", err)
	}

	if err := vf.SaveToFile(vaultfilePath); err != nil {
		return fmt.Errorf("failed to save vaultfile: %w", err)
	}

	fmt.Printf("Secret '%s' has been deleted from vaultfile at %s.\n", secretName, vaultfilePath)
	return nil
}

func getUsername() string {
	if username := os.Getenv("USER"); username != "" {
		return username
	}
	if username := os.Getenv("USERNAME"); username != "" {
		return username
	}
	return "user"
}
