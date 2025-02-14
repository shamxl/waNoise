package waNoise

import (
	"crypto/cipher"
	"sync/atomic"

	"golang.org/x/crypto/curve25519"
)

type NoiseHandler struct {
  clientKeyPair *KeyPair
  serverKeyPair *KeyPair
  hash []byte
  salt []byte
  key cipher.AEAD
  counter uint32
}

func (nh *NoiseHandler) Authenticate (data []byte) {
  nh.hash = sha256Sum(append(nh.hash, data...))
}

func (nh *NoiseHandler) MixIntoKey (data []byte) {
  nh.counter = 0
  write, read, err := extractAndExpand(nh.salt, data)
  if err != nil {
    panic (err)
  }

  nh.salt = write
  key, err := NewAESGCM(read)
  if err != nil {
    panic (err)
  }
  nh.key = key
}

func (nh *NoiseHandler) MixSharedKey (priv, pub [32]byte) {
  secret, err := curve25519.X25519(priv[:], pub[:])
  if err != nil {
    panic (err)
  }

  nh.MixIntoKey (secret)
}

func (nh *NoiseHandler) PostIncrementCounter () uint32 {
  c := atomic.AddUint32(&nh.counter, 1)

  return c - 1
}

func (nh *NoiseHandler) Decrypt (ciphertext []byte) ([]byte, error) {
  dec, err := nh.key.Open(nil, generateIV(nh.PostIncrementCounter()), ciphertext, nh.hash)
  if err == nil {
    nh.Authenticate(ciphertext)
  }
  return dec, err
}

func (nh *NoiseHandler) StartHandshake () {
  mode := []byte(NOISE_MODE)
  if len(mode) == 32 {
    nh.hash = mode
  } else {
    nh.hash = sha256Sum(mode)
  }

  nh.salt = nh.hash
  key, err := NewAESGCM(nh.hash)
  if err != nil {
    panic (err)
  }
  nh.key = key
  nh.Authenticate(WA_NOISE_HEADER)
}


