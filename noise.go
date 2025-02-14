package waNoise

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"io"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

type KeyPair  struct {
  Public [32]byte
  Private [32]byte
}

func NewKeyPair () *KeyPair {
  k := &KeyPair{}

  var privKey [32]byte
  rand.Read(privKey[:])
  var pubKey [32]byte
  curve25519.ScalarBaseMult(&pubKey, &privKey)

  k.Private = privKey
  k.Public = pubKey
  return k
}


func sha256Sum (data []byte) []byte {
  h := sha256.Sum256(data)
  return h[:]
}

func generateIV (count uint32) []byte {
  iv := make ([]byte, 12)
  binary.LittleEndian.PutUint32(iv[8:], count)

  return iv
}

func extractAndExpand (salt, data []byte) ([]byte, []byte, error) {
  h := hkdf.New(sha256.New, data, salt, nil)
  var write []byte = make([]byte, 32)
  var read []byte = make([]byte, 32)

  _, err := io.ReadFull(h, write)

  if err != nil {
    return nil, nil, err
  }
  _, err = io.ReadFull(h, read) 

  if err != nil {
    return nil, nil, err
  }

  return write, read, nil
}

func NewAESGCM (secretKey []byte) (cipher.AEAD, error) {
  block, err := aes.NewCipher(secretKey)
  if err != nil {
    return nil, err
  }

  gcm, err := cipher.NewGCM(block)
  if err != nil {
    return nil, err
  }

  return gcm, nil
}


