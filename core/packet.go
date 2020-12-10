package core

import "net"

func ListenPacket(network, address string, cipher PacketConnCipher) (net.PacketConn, error) {
	ln, err := net.ListenPacket(network, address)
	if err != nil {
		return nil, err
	}

	return cipher.PacketConn(ln), nil
}
