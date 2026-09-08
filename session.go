package sdr

import (
	"fmt"
	"math/rand/v2"
	"mtobject/sdr/gen/protos"
	"net"
	"net/netip"
	"reflect"
	"time"

	"google.golang.org/protobuf/proto"
)

type clientKey struct {
	addr         netip.AddrPort
	connectionID uint32
}

type serverKey struct {
	addr      netip.AddrPort
	sessionID uint32
}

type clientDataMessage struct {
	header           messageHeader
	stats            *protos.CMsgSteamDatagramConnectionStatsClientToRouter
	timeSincePrevE2E time.Duration
	body             []byte
}

type serverDataMessage struct {
	header           messageHeader
	stats            *protos.CMsgSteamDatagramConnectionStatsServerToRouter
	timeSincePrevE2E time.Duration
	body             []byte
}

type sessionChannels struct {
	clientMessages chan any
	serverMessages chan any

	sendClientStatsSignal <-chan time.Time
	sendServerStatsSignal <-chan time.Time
}

type session struct {
	sessionChannels

	clientConn           *net.UDPConn
	serverConn           *net.UDPConn
	clientAddr           netip.AddrPort
	serverAddr           netip.AddrPort
	clientConnectionID   uint32
	serverSessionID      uint32
	clientIdentity       string
	serverIdentity       string
	routingSecret        uint64
	clientStats          stats
	serverStats          stats
	sendClientStatsTimer *time.Timer
	sendServerStatsTimer *time.Timer
}

func (relay *Relay) findClientSession(addr netip.AddrPort, connID uint32) *sessionChannels {
	relay.sessionLock.RLock()
	session, exists := relay.clientSessions[clientKey{
		addr:         addr,
		connectionID: connID,
	}]
	if !exists {
		return nil
	}
	relay.sessionLock.RUnlock()

	return &session.sessionChannels
}

func (relay *Relay) findServerSession(addr netip.AddrPort, sessionID uint32) *sessionChannels {
	relay.sessionLock.RLock()
	session, exists := relay.serverSessions[serverKey{
		addr:      addr,
		sessionID: sessionID,
	}]
	if !exists {
		return nil
	}
	relay.sessionLock.RUnlock()

	return &session.sessionChannels
}

func (relay *Relay) handleClientCtrlMessage(
	addr netip.AddrPort,
	msg proto.Message,
	getSessionID func() uint32,
	rawMsg []byte,
) {
	if err := proto.Unmarshal(rawMsg, proto.Message(msg)); err != nil {
		fmt.Printf("failed to decode ctrl packet from client: %s\n", err)
		return
	}

	if session := relay.findClientSession(addr, getSessionID()); session != nil {
		session.clientMessages <- msg
	} else {
		// TODO: send noconnection
	}
}

func (relay *Relay) handleServerCtrlMessage(
	addr netip.AddrPort,
	msg proto.Message,
	getSessionID func() uint32,
	rawMsg []byte,
) {
	if err := proto.Unmarshal(rawMsg, proto.Message(msg)); err != nil {
		fmt.Printf("failed to decode ctrl packet from server: %s\n", err)
		return
	}

	if session := relay.findServerSession(addr, getSessionID()); session != nil {
		session.serverMessages <- msg
	} else {
		// TODO: send noconnection
	}
}

func (relay *Relay) createSession(
	clientAddr netip.AddrPort,
	serverAddr netip.AddrPort,
	clientIdentity string,
	serverIdentity string,
	clientConnID uint32,
	routingSecret uint64,
) *session {
	relay.sessionLock.Lock()
	defer relay.sessionLock.Unlock()

	clientKey := clientKey{addr: clientAddr, connectionID: clientConnID}
	if session, present := relay.clientSessions[clientKey]; present {
		return session
	}

	var serverSessionID uint32 = rand.Uint32()
	if serverSessionID == 0 {
		// unsure if this is a valid value, but let's be safe
		return nil
	}

	serverKey := serverKey{addr: serverAddr, sessionID: serverSessionID}
	if _, present := relay.serverSessions[serverKey]; present {
		// we already have a session with the same server session id, but for a different client.
		return nil
	}

	session := &session{
		sessionChannels: sessionChannels{
			clientMessages: make(chan any),
			serverMessages: make(chan any),
		},

		clientConn:         relay.clientConn,
		serverConn:         relay.serverConn,
		clientAddr:         clientAddr,
		serverAddr:         serverAddr,
		clientConnectionID: clientConnID,
		serverSessionID:    serverSessionID,
		clientIdentity:     clientIdentity,
		serverIdentity:     serverIdentity,
		routingSecret:      routingSecret,
		clientStats:        newStats(),
		serverStats:        newStats(),
	}

	session.sendClientStatsTimer = time.NewTimer(0)
	session.sendServerStatsTimer = time.NewTimer(0)
	session.sendClientStatsSignal = session.sendClientStatsTimer.C
	session.sendServerStatsSignal = session.sendServerStatsTimer.C

	relay.clientSessions[clientKey] = session
	relay.serverSessions[serverKey] = session

	return session
}

func (session *session) recv() {
	for {
		select {
		case msg := <-session.clientMessages:
			session.handleClientMessage(msg)
		case msg := <-session.serverMessages:
			session.handleServerMessage(msg)
		case now := <-session.sendClientStatsSignal:
			session.sendStatsToClient(now, nil)
		case now := <-session.sendServerStatsSignal:
			session.sendStatsToServer(now, nil)
		}
	}
}

func (session *session) handleClientMessage(msg any) {
	switch msg := msg.(type) {
	case *protos.CMsgSteamDatagramConnectRequest:
		session.handleClientConnectRequest(msg)
	case *protos.CMsgSteamDatagramConnectionStatsClientToRouter:
		session.handleClientStats(msg)
	case *protos.CMsgSteamDatagramConnectionClosed:
		session.handleClientConnectionClosed(msg)
	case *protos.CMsgSteamDatagramNoConnection:
		session.handleClientNoConnection(msg)
	case clientDataMessage:
		session.handleClientData(msg)
	default:
		panic(fmt.Sprintf(`unhandled message type "%s"`, reflect.TypeOf(msg)))
	}
}

func (session *session) handleServerMessage(msg any) {
	switch msg := msg.(type) {
	case *protos.CMsgSteamDatagramConnectOK:
		session.handleServerConnectOK(msg)
	case *protos.CMsgSteamDatagramConnectionStatsServerToRouter:
		session.handleServerStats(msg)
	case *protos.CMsgSteamDatagramConnectionClosed:
		session.handleServerConnectionClosed(msg)
	case *protos.CMsgSteamDatagramNoConnection:
		session.handleServerNoConnection(msg)
	case serverDataMessage:
		session.handleServerData(msg)
	default:
		panic(fmt.Sprintf(`unhandled message type "%s"`, reflect.TypeOf(msg)))
	}
}
