package crypto

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"

	"github.com/hyperledger/fabric-gateway/pkg/identity"
)

type Credentials struct {
	Certificate string `json:"certificate"`
	PrivateKey  string `json:"privateKey"`
}

type Data struct {
	Credentials Credentials `json:"credentials"`
}

// getSignFn returns a function that generates a digital signature from a message digest using a private key.
func getSignFn(privateKeyPEM []byte) identity.Sign {

	privateKey, err := identity.PrivateKeyFromPEM([]byte(privateKeyPEM))
	if err != nil {
		panic(err)
	}

	sign, err := identity.NewPrivateKeySign(privateKey)
	if err != nil {
		panic(err)
	}

	return sign
}

// get the certificate from the wallet
func getCertificate(identityPath string) (*Data, error) {
	fileData, err := os.ReadFile(identityPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %w", err)
	}

	var data Data
	err = json.Unmarshal(fileData, &data)
	if err != nil {
		return nil, fmt.Errorf("failed to parse JSON: %w", err)
	}
	return &data, nil
}

// extract private key from certificate
func GetPrivateKey(identityPath string) ([]byte, error) {
	data, err := getCertificate(identityPath)
	if err != nil {
		return nil, fmt.Errorf("failed to get certificate: %w", err)
	}

	privateKeyPEM := []byte(data.Credentials.PrivateKey)
	return privateKeyPEM, nil
}

// extract public key from certificate
func GetPublicKey(filePath string) ([]byte, error) {
	data, err := getCertificate(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to get certificate: %w", err)
	}

	certBytes := []byte(data.Credentials.Certificate)

	block, _ := pem.Decode(certBytes)
	if block == nil {
		return nil, fmt.Errorf("failed to decode certificate PEM")
	}

	// Parse the certificate
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %w", err)
	}

	// Extract the ECDSA public key
	ecdsaPublicKey := cert.PublicKey.(*ecdsa.PublicKey)

	// Marshal the ECDSA public key to DER format
	publicKeyDER, err := x509.MarshalPKIXPublicKey(ecdsaPublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal public key: %w", err)
	}
	// Encode the public key to PEM format
	publicKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyDER,
	})

	return publicKeyPEM, nil
}

// digitally sign a message, and return a base-64 encoded signature string
func SignMessage(privatekeyPEM []byte, msg []byte) (string, error) {
	// Sign the message using the provided signing function
	signFn := getSignFn(privatekeyPEM)

	signature, err := signFn(msg)
	if err != nil {
		return "", err
	}

	eSignature := base64.StdEncoding.EncodeToString(signature)
	if err != nil {
		return "", err
	}

	return eSignature, nil
}

// verify if digital signature of message is valid
// inputs:  publicKeyPEM - public key of signer
//
//	jsonMessage -  message signed with private key
//	encodedSignature - base-64 digital signature
func VerifySignature(publicKeyPEM []byte, jsonMessage []byte, encodedSignature string) (bool, error) {
	block, _ := pem.Decode(publicKeyPEM)
	if block == nil {
		err := errors.New("PEM decode error")
		return false, fmt.Errorf("failed to decode public key PEM %v", err)
	}

	publicKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return false, fmt.Errorf("failed to parse public key %v", err)
	}

	ecdsaPublicKey, ok := publicKey.(*ecdsa.PublicKey)
	if !ok {
		err := errors.New("ecdsa public key conversion error")
		return false, fmt.Errorf("failed to convert public key to ECDSA public key %v", err)
	}

	signatureBytes, err := base64.StdEncoding.DecodeString(encodedSignature)
	if err != nil {
		return false, fmt.Errorf("failed to decode signature %v", err)
	}

	// Verify the signature using the public key
	valid := ecdsa.VerifyASN1(ecdsaPublicKey, jsonMessage, signatureBytes)

	return valid, nil
}
