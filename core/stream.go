package core

import "net"

type Listener struct {
	net.Listener
	StreamConnCipher
}

func Listen(network, address string, cipher StreamConnCipher) (net.Listener, error) {
	ln, err := net.Listen(network, address)
	if err != nil {
		return nil, err
	}

	return &Listener{ln, cipher}, nil
}

func (s *Listener) Accept() (net.Conn, error) {
	client, err := s.Listener.Accept()
	if err != nil {
		return nil, err
	}

	return s.StreamConn(client), nil
}

func Dial(network, address string, cipher StreamConnCipher) (net.Conn, error) {
	client, err := net.Dial(network, address)
	if err != nil {
		return nil, err
	}

	return cipher.StreamConn(client), nil
}
