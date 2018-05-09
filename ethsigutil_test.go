package ethsigutil

import (
	"encoding/hex"
	"testing"

	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/stretchr/testify/assert"
)

func TestHashMessage(t *testing.T) {
	assert := assert.New(t)
	messageText := "Hello World"
	expectedHash := "0xa1de988600a42c4b4ab089b619297c17d53cffae5d5120d82d8a92d0bb3b78f2"
	messageHash := HashMessage([]byte(messageText))

	// Add 0x as per Ethereum
	fmtHash := "0x" + hex.EncodeToString(messageHash)

	assert.Equal(expectedHash, fmtHash)
}

func TestRecover(t *testing.T) {
	assert := assert.New(t)
	// From web3 1.0 example
	encMsg := "0x1da44b586eb0729ff70a73c326926f6ed5a25f5b056e7f47fbc6e58d86871655"
	expectedAddr := "0x2c7536E3605D9C16a7a3D7b1898e529396a65c23"
	// Sig encoded by web3.js
	encSig := "0xb91467e570a6466aa9e9876cbcd013baba02900b8979d43fe208a4a4f339f5fd6007e74cd82e037b800186422fc2da167c747ef045e5d18a5f5d4300f8e1a0291c"

	messageHash, err := hexutil.Decode(encMsg)
	assert.NoError(err)

	sig, err := hexutil.Decode(encSig)
	assert.NoError(err)

	addr, err := Recover(messageHash, sig)
	assert.NoError(err)
	assert.Equal(expectedAddr, addr)
}

func TestRecoverString(t *testing.T) {
	assert := assert.New(t)
	// From web3 1.0 example
	encMsg := "0x1da44b586eb0729ff70a73c326926f6ed5a25f5b056e7f47fbc6e58d86871655"
	expectedAddr := "0x2c7536E3605D9C16a7a3D7b1898e529396a65c23"
	// Sig encoded by web3.js
	encSig := "0xb91467e570a6466aa9e9876cbcd013baba02900b8979d43fe208a4a4f339f5fd6007e74cd82e037b800186422fc2da167c747ef045e5d18a5f5d4300f8e1a0291c"

	addr, err := RecoverString(encMsg, encSig)
	assert.NoError(err)
	assert.Equal(expectedAddr, addr)
}

func BenchmarkRecover(b *testing.B) {
	// From web3 1.0 example
	encMsg := "0x1da44b586eb0729ff70a73c326926f6ed5a25f5b056e7f47fbc6e58d86871655"
	// Sig encoded by web3.js
	encSig := "0xb91467e570a6466aa9e9876cbcd013baba02900b8979d43fe208a4a4f339f5fd6007e74cd82e037b800186422fc2da167c747ef045e5d18a5f5d4300f8e1a0291c"

	messageHash, _ := hexutil.Decode(encMsg)

	sig, _ := hexutil.Decode(encSig)

	for i := 0; i < b.N; i++ {
		Recover(messageHash, sig)
	}
}

func TestSign(t *testing.T) {
	assert := assert.New(t)
	encPk := "0x4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318"
	messageText := "Some data"
	expectedSig := "0xb91467e570a6466aa9e9876cbcd013baba02900b8979d43fe208a4a4f339f5fd6007e74cd82e037b800186422fc2da167c747ef045e5d18a5f5d4300f8e1a02901"

	messageHash := HashMessage([]byte(messageText))

	pk, err := hexutil.Decode(encPk)
	assert.NoError(err)

	sig, err := Sign(messageHash, pk)
	assert.NoError(err)

	encSig := hexutil.Encode(sig)
	assert.Equal(len(expectedSig), len(encSig))
	assert.Equal(expectedSig, encSig)
}

func TestSignString(t *testing.T) {
	assert := assert.New(t)
	encPk := "0x4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318"
	encMsg := "0x1da44b586eb0729ff70a73c326926f6ed5a25f5b056e7f47fbc6e58d86871655"
	expectedSig := "0xb91467e570a6466aa9e9876cbcd013baba02900b8979d43fe208a4a4f339f5fd6007e74cd82e037b800186422fc2da167c747ef045e5d18a5f5d4300f8e1a02901"

	encSig, err := SignString(encMsg, encPk)
	assert.NoError(err)
	assert.Equal(expectedSig, encSig)
}
