package sdr

import (
	"crypto/ecdh"
	"fmt"
	"net"
	"net/netip"
	"sync"
)

type Relay struct {
	popid          [4]byte
	privateKey     *ecdh.PrivateKey
	clientConn     *net.UDPConn
	serverConn     *net.UDPConn
	sessionLock    sync.RWMutex
	clientSessions map[clientKey]*session
	serverSessions map[serverKey]*session
}

func NewRelay(
	popid [4]byte,
	privateKey *ecdh.PrivateKey,
	addr netip.AddrPort,
) (*Relay, error) {
	clientConn, err := net.ListenUDP("udp4", net.UDPAddrFromAddrPort(addr))
	if err != nil {
		return nil, err
	}

	serverConn, err := net.ListenUDP("udp4", nil)
	if err != nil {
		return nil, err
	}

	fmt.Println("listening on", clientConn.LocalAddr())
	return &Relay{
		popid:      popid,
		privateKey: privateKey,

		clientConn: clientConn,
		serverConn: serverConn,

		clientSessions: make(map[clientKey]*session),
		serverSessions: make(map[serverKey]*session),
	}, nil
}

func (relay *Relay) Run() {
	var wg sync.WaitGroup
	wg.Go(relay.handleClientPackets)
	wg.Go(relay.handleServerPackets)

	wg.Wait()
}
