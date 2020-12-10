package shadowstream

import (
	"bytes"
	"crypto/cipher"
	"crypto/rand"
	"io"
	"net"
)

const bufSize = 1024 * 2

type Writer struct {
	io.Writer
	cipher.Stream
	buf []byte
}

func NewWriter(w io.Writer, s cipher.Stream) io.Writer {
	return &Writer{Writer: w, Stream: s, buf: make([]byte, bufSize)}
}

func (w *Writer) ReadFrom(r io.Reader) (n int64, err error) {
	for {
		buf := w.buf
		nr, er := r.Read(buf)
		if nr > 0 {
			n += int64(nr)
			buf = buf[:nr]
			w.XORKeyStream(buf, buf)
			_, ew := w.Writer.Write(buf)
			if ew != nil {
				err = ew
				return
			}
		}

		if er != nil {
			if er != io.EOF {
				err = er
			}
			return
		}
	}
}

func (w *Writer) Write(b []byte) (int, error) {
	n, err := w.ReadFrom(bytes.NewBuffer(b))
	return int(n), err
}

type Reader struct {
	io.Reader
	cipher.Stream
	buf []byte
}

func NewReader(r io.Reader, s cipher.Stream) io.Reader {
	return &Reader{Reader: r, Stream: s, buf: make([]byte, bufSize)}
}

func (r *Reader) Read(b []byte) (int, error) {

	n, err := r.Reader.Read(b)
	if err != nil {
		return 0, err
	}
	b = b[:n]
	r.XORKeyStream(b, b)
	return n, nil
}

func (r *Reader) WriteTo(w io.Writer) (n int64, err error) {
	for {
		buf := r.buf
		nr, er := r.Read(buf)
		if nr > 0 {
			nw, ew := w.Write(buf[:nr])
			n += int64(nw)

			if ew != nil {
				err = ew
				return
			}
		}

		if er != nil {
			if er != io.EOF {
				err = er
			}
			return
		}
	}
}

type Conn struct {
	net.Conn
	Cipher
	r *Reader
	w *Writer

	riv []byte
	wiv []byte
}

func NewConn(c net.Conn, ciph Cipher) net.Conn {
	return &Conn{Conn: c, Cipher: ciph}
}

func (c *Conn) initReader() error {
	if c.r == nil {
		iv, err := c.ObtainRIV()
		if err != nil {
			return err
		}

		c.r = &Reader{Reader: c.Conn, Stream: c.Decrypter(iv), buf: make([]byte, bufSize)}
	}

	return nil
}

func (c *Conn) Read(b []byte) (int, error) {
	if c.r == nil {
		if err := c.initReader(); err != nil {
			return 0, err
		}
	}

	return c.r.Read(b)
}

func (c *Conn) WriteTo(w io.Writer) (int64, error) {
	if c.r == nil {
		if err := c.initReader(); err != nil {
			return 0, err
		}
	}

	return c.r.WriteTo(w)
}

func (c *Conn) initWriter() error {
	if c.w == nil {
		iv, err := c.ObtainWIV()
		if err != nil {
			return err
		}

		if _, err := c.Conn.Write(iv); err != nil {
			return err
		}

		c.w = &Writer{Writer: c.Conn, Stream: c.Encrypter(iv), buf: make([]byte, bufSize)}
	}

	return nil
}

func (c *Conn) Write(b []byte) (int, error) {
	if c.w == nil {
		if err := c.initWriter(); err != nil {
			return 0, err
		}
	}

	return c.w.Write(b)
}

func (c *Conn) ReadFrom(r io.Reader) (int64, error) {
	if c.w == nil {
		if err := c.initWriter(); err != nil {
			return 0, err
		}
	}

	return c.w.ReadFrom(r)
}

func (c *Conn) ObtainWIV() ([]byte, error) {
	if len(c.wiv) == c.IVSize() {
		return c.wiv, nil
	}

	iv := make([]byte, c.IVSize())

	if _, err := rand.Read(iv); err != nil {
		return nil, err
	}

	c.wiv = iv

	return iv, nil
}

func (c *Conn) ObtainRIV() ([]byte, error) {
	if len(c.riv) == c.IVSize() {
		return c.riv, nil
	}

	iv := make([]byte, c.IVSize())

	if _, err := io.ReadFull(c.Conn, iv); err != nil {
		return nil, err
	}

	c.riv = iv

	return iv, nil
}
