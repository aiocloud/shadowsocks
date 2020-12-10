package core

import (
	"crypto/md5"
	"errors"
	"net"
	"strings"

	"github.com/aiocloud/shadowsocks/shadowaead"
	"github.com/aiocloud/shadowsocks/shadowstream"
)

type Cipher interface {
	StreamConnCipher
	PacketConnCipher
}

type StreamConnCipher interface {
	StreamConn(net.Conn) net.Conn
}

type PacketConnCipher interface {
	PacketConn(net.PacketConn) net.PacketConn
}

var ErrCipherNotSupported = errors.New("Cipher not supported")

var AEADList = map[string]struct {
	KeySize int
	New     func([]byte) (shadowaead.Cipher, error)
}{
	"AES-128-GCM":             {16, shadowaead.AESGCM},
	"AES-192-GCM":             {24, shadowaead.AESGCM},
	"AES-256-GCM":             {32, shadowaead.AESGCM},
	"CHACHA20-IETF-POLY1305":  {32, shadowaead.Chacha20Poly1305},
	"XCHACHA20-IETF-POLY1305": {32, shadowaead.XChacha20Poly1305},
}

var StreamList = map[string]struct {
	KeySize int
	New     func([]byte) (shadowstream.Cipher, error)
}{
	"RC4-MD5":       {16, shadowstream.RC4MD5},
	"AES-128-CFB":   {16, shadowstream.AESCFB},
	"AES-192-CFB":   {24, shadowstream.AESCFB},
	"AES-256-CFB":   {32, shadowstream.AESCFB},
	"AES-128-CTR":   {16, shadowstream.AESCTR},
	"AES-192-CTR":   {24, shadowstream.AESCTR},
	"AES-256-CTR":   {32, shadowstream.AESCTR},
	"CHACHA20":      {32, shadowstream.Chacha20},
	"CHACHA20-IETF": {32, shadowstream.Chacha20IETF},
	"XCHACHA20":     {32, shadowstream.Xchacha20},
}

func ListCipher() []string {
	var l []string

	for k := range AEADList {
		l = append(l, k)
	}

	for k := range StreamList {
		l = append(l, k)
	}

	return l
}

func PickCipher(name string, key []byte, password string) (Cipher, error) {
	name = strings.ToUpper(name)
	if name == "NONE" {
		return &dummy{}, nil
	}

	if choice, ok := AEADList[name]; ok {
		if len(key) == 0 {
			key = KDF(password, choice.KeySize)
		}

		if len(key) != choice.KeySize {
			return nil, shadowaead.KeySizeError(choice.KeySize)
		}

		cipher, err := choice.New(key)
		if err != nil {
			return nil, err
		}

		return &AEADCipher{cipher, key}, nil
	}

	if choice, ok := StreamList[name]; ok {
		if len(key) == 0 {
			key = KDF(password, choice.KeySize)
		}

		if len(key) != choice.KeySize {
			return nil, shadowstream.KeySizeError(choice.KeySize)
		}

		cipher, err := choice.New(key)
		if err != nil {
			return nil, err
		}

		return &StreamCipher{cipher, key}, nil
	}

	return nil, ErrCipherNotSupported
}

type AEADCipher struct {
	shadowaead.Cipher

	Secret []byte
}

func (a *AEADCipher) StreamConn(c net.Conn) net.Conn { return shadowaead.NewConn(c, a) }
func (a *AEADCipher) PacketConn(c net.PacketConn) net.PacketConn {
	return shadowaead.NewPacketConn(c, a)
}

type StreamCipher struct {
	shadowstream.Cipher

	Secret []byte
}

func (s *StreamCipher) StreamConn(c net.Conn) net.Conn { return shadowstream.NewConn(c, s) }
func (s *StreamCipher) PacketConn(c net.PacketConn) net.PacketConn {
	return shadowstream.NewPacketConn(c, s)
}

type dummy struct{}

func (dummy) StreamConn(c net.Conn) net.Conn             { return c }
func (dummy) PacketConn(c net.PacketConn) net.PacketConn { return c }

func KDF(s string, length int) []byte {
	var a, b []byte
	h := md5.New()

	for len(a) < length {
		_, _ = h.Write(b)
		_, _ = h.Write([]byte(s))
		a = h.Sum(a)
		b = a[len(a)-h.Size():]
		h.Reset()
	}

	return a[:length]
}
