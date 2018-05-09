// Package ethsigutil provides helpful utility functions for working with
// Ethereum signatures
package ethsigutil

import (
	"fmt"

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
	pk := crypto.ToECDSAPub(rpk)
	addr := crypto.PubkeyToAddress(*pk)
	return addr.Hex(), nil
}

// HashMessage hashes the given message for use with the recover function
// The text to be hashed is computed as follows: "\x19Ethereum Signed Message:\n" + len(message) + message
func HashMessage(data []byte) []byte {
	msg := fmt.Sprintf("\x19Ethereum Signed Message:\n%d%s", len(data), data)
	return crypto.Keccak256([]byte(msg))
}
