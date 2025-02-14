package waNoise

const (
  NOISE_MODE = "Noise_XX_25519_AESGCM_SHA256\x00\x00\x00\x00"
  WA_MAGIC_NUMBER  = 6
  WA_DICT_VERSION  = 2
)

var WA_NOISE_HEADER []byte = []byte{'W', 'A', WA_MAGIC_NUMBER, WA_DICT_VERSION}
