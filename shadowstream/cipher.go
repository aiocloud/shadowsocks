package shadowstream

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rc4"
	"strconv"

	"github.com/aead/chacha20"
	"github.com/aead/chacha20/chacha"
)

type Cipher interface {
	IVSize() int
	Encrypter(iv []byte) cipher.Stream
	Decrypter(iv []byte) cipher.Stream
}

type KeySizeError int

func (e KeySizeError) Error() string {
	return "key size error: need " + strconv.Itoa(int(e)) + " bytes"
}

type ctrStream struct{ cipher.Block }

func (b *ctrStream) IVSize() int                       { return b.BlockSize() }
func (b *ctrStream) Decrypter(iv []byte) cipher.Stream { return b.Encrypter(iv) }
func (b *ctrStream) Encrypter(iv []byte) cipher.Stream { return cipher.NewCTR(b, iv) }

func AESCTR(key []byte) (Cipher, error) {
	blk, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return &ctrStream{blk}, nil
}

type cfbStream struct{ cipher.Block }

func (b *cfbStream) IVSize() int                       { return b.BlockSize() }
func (b *cfbStream) Decrypter(iv []byte) cipher.Stream { return cipher.NewCFBDecrypter(b, iv) }
func (b *cfbStream) Encrypter(iv []byte) cipher.Stream { return cipher.NewCFBEncrypter(b, iv) }

func AESCFB(key []byte) (Cipher, error) {
	blk, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return &cfbStream{blk}, nil
}

type chacha20key []byte

func (k chacha20key) IVSize() int                       { return chacha.NonceSize }
func (k chacha20key) Decrypter(iv []byte) cipher.Stream { return k.Encrypter(iv) }
func (k chacha20key) Encrypter(iv []byte) cipher.Stream {
	ciph, err := chacha20.NewCipher(iv, k)
	if err != nil {
		panic(err)
	}

	return ciph
}

func Chacha20(key []byte) (Cipher, error) {
	if len(key) != chacha.KeySize {
		return nil, KeySizeError(chacha.KeySize)
	}

	return chacha20key(key), nil
}

type chacha20ietfkey []byte

func (k chacha20ietfkey) IVSize() int                       { return chacha.INonceSize }
func (k chacha20ietfkey) Decrypter(iv []byte) cipher.Stream { return k.Encrypter(iv) }
func (k chacha20ietfkey) Encrypter(iv []byte) cipher.Stream {
	ciph, err := chacha20.NewCipher(iv, k)
	if err != nil {
		panic(err)
	}
	return ciph
}

func Chacha20IETF(key []byte) (Cipher, error) {
	if len(key) != chacha.KeySize {
		return nil, KeySizeError(chacha.KeySize)
	}
	return chacha20ietfkey(key), nil
}

type xchacha20key []byte

func (k xchacha20key) IVSize() int                       { return chacha.XNonceSize }
func (k xchacha20key) Decrypter(iv []byte) cipher.Stream { return k.Encrypter(iv) }
func (k xchacha20key) Encrypter(iv []byte) cipher.Stream {
	ciph, err := chacha20.NewCipher(iv, k)
	if err != nil {
		panic(err)
	}
	return ciph
}

func Xchacha20(key []byte) (Cipher, error) {
	if len(key) != chacha.KeySize {
		return nil, KeySizeError(chacha.KeySize)
	}
	return xchacha20key(key), nil
}

type rc4Md5Key []byte

func (k rc4Md5Key) IVSize() int                       { return 16 }
func (k rc4Md5Key) Decrypter(iv []byte) cipher.Stream { return k.Encrypter(iv) }
func (k rc4Md5Key) Encrypter(iv []byte) cipher.Stream {
	h := md5.New()
	_, _ = h.Write(k)
	_, _ = h.Write(iv)

	rc4key := h.Sum(nil)
	ciph, err := rc4.NewCipher(rc4key)
	if err != nil {
		panic(err)
	}

	return ciph
}

func RC4MD5(key []byte) (Cipher, error) {
	return rc4Md5Key(key), nil
}
