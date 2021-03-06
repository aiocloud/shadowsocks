package shadowaead

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha1"
	"io"
	"strconv"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

type Cipher interface {
	KeySize() int
	SaltSize() int
	Encrypter(salt []byte) (cipher.AEAD, error)
	Decrypter(salt []byte) (cipher.AEAD, error)
}

type KeySizeError int

func (e KeySizeError) Error() string {
	return "key size error: need " + strconv.Itoa(int(e)) + " bytes"
}

func HKDFSHA1(secret, salt, info, outkey []byte) {
	r := hkdf.New(sha1.New, secret, salt, info)
	if _, err := io.ReadFull(r, outkey); err != nil {
		panic(err)
	}
}

type metaCipher struct {
	psk      []byte
	makeAEAD func(key []byte) (cipher.AEAD, error)
}

func (a *metaCipher) KeySize() int { return len(a.psk) }
func (a *metaCipher) SaltSize() int {
	if ks := a.KeySize(); ks > 16 {
		return ks
	}
	return 16
}
func (a *metaCipher) Encrypter(salt []byte) (cipher.AEAD, error) {
	subkey := make([]byte, a.KeySize())
	HKDFSHA1(a.psk, salt, []byte("ss-subkey"), subkey)
	return a.makeAEAD(subkey)
}
func (a *metaCipher) Decrypter(salt []byte) (cipher.AEAD, error) {
	subkey := make([]byte, a.KeySize())
	HKDFSHA1(a.psk, salt, []byte("ss-subkey"), subkey)
	return a.makeAEAD(subkey)
}

func aesGCM(key []byte) (cipher.AEAD, error) {
	blk, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(blk)
}

func AESGCM(psk []byte) (Cipher, error) {
	switch l := len(psk); l {
	case 16, 24, 32:
	default:
		return nil, aes.KeySizeError(l)
	}
	return &metaCipher{psk: psk, makeAEAD: aesGCM}, nil
}

func Chacha20Poly1305(psk []byte) (Cipher, error) {
	if len(psk) != chacha20poly1305.KeySize {
		return nil, KeySizeError(chacha20poly1305.KeySize)
	}
	return &metaCipher{psk: psk, makeAEAD: chacha20poly1305.New}, nil
}

func XChacha20Poly1305(psk []byte) (Cipher, error) {
	if len(psk) != chacha20poly1305.KeySize {
		return nil, KeySizeError(chacha20poly1305.KeySize)
	}

	return &metaCipher{psk: psk, makeAEAD: chacha20poly1305.NewX}, nil
}
