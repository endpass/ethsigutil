// Package ethsigutil provides helpful utility functions for working with
// Ethereum signatures
package ethsigutil

import (
	"fmt"

	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
)

// Recover recovers the Ethereum address used to sign a message
// This function corresponds to web3.eth.accounts.recover in web3.js
// The address is returned as a hex string
func Recover(messageHash, sig []byte) (string, error) {
	if len(sig) != 65 {
		return "", fmt.Errorf("signature must be 65 bytes long")
	}
	if sig[64] != 27 && sig[64] != 28 {
		return "", fmt.Errorf("invalid Ethereum signature (V is not 27 or 28)")
	}
	sig[64] -= 27 // Transform yellow paper V from 27/28 to 0/1
	rpk, err := crypto.Ecrecover(messageHash, sig)
	if err != nil {
		return "", err
	}

	pk, err := crypto.UnmarshalPubkey(rpk)
	if err != nil {
		return "", err
	}

	addr := crypto.PubkeyToAddress(*pk)
	return addr.Hex(), nil
}

// RecoverString is a convenience function that lets Recover be used directly
// with a hex encoded message hash and signature
func RecoverString(messageHash, sig string) (string, error) {
	msgBytes, err := hexutil.Decode(messageHash)
	if err != nil {
		return "", err
	}
	sigBytes, err := hexutil.Decode(sig)
	if err != nil {
		return "", err
	}
	return Recover(msgBytes, sigBytes)
}

// HashMessage hashes the given message for use with the recover function
// The text to be hashed is computed as follows: "\x19Ethereum Signed Message:\n" + len(message) + message
func HashMessage(data []byte) []byte {
	msg := fmt.Sprintf("\x19Ethereum Signed Message:\n%d%s", len(data), data)
	return crypto.Keccak256([]byte(msg))
}

// Sign calculates a signature for a hashed message using the given private key
// Arbitrary data should first be hashed with HashMessage
// Returns sig that can be used with Recover
func Sign(messageHash, privKey []byte) ([]byte, error) {
	pk, err := crypto.ToECDSA(privKey)
	if err != nil {
		return nil, err
	}
	return crypto.Sign(messageHash, pk)
}

// SignString is a convenience function that lets Sign be used with a
// hex-encoded message hash and private key, and returns the hex-encoded
// signature string
// The message should already have been hashed with Ethereum Signed Message
// prefix
func SignString(messageHash, privKey string) (string, error) {
	msgBytes, err := hexutil.Decode(messageHash)
	if err != nil {
		return "", err
	}
	pkBytes, err := hexutil.Decode(privKey)
	if err != nil {
		return "", err
	}
	sig, err := Sign(msgBytes, pkBytes)
	if err != nil {
		return "", err
	}
	return hexutil.Encode(sig), nil
}
