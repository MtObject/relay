package sdr

import (
	"encoding/binary"
	"fmt"
	"mtobject/sdr/gen/protos"
	"net/netip"
	"time"
)

func (relay *Relay) handleClientPackets() {
	for {
		buf := make([]byte, maxPacketLen)
		n, addr, err := relay.clientConn.ReadFromUDPAddrPort(buf[:])
		if err != nil {
			// FIXME: don't panic
			panic(err)
		}

		relay.handleClientPacket(addr, buf[:n])
	}
}

func (relay *Relay) handleClientPacket(addr netip.AddrPort, pkt []byte) {
	if len(pkt) < 1 {
		fmt.Println("packet too small")
		return
	}

	cmd := pkt[0]
	body := pkt[1:]
	switch getCmdType(cmd) {
	case packetTypeCtrl:
		{
			ctrl := protos.ESteamDatagramMsgID(cmd)
			switch ctrl {
			case protos.ESteamDatagramMsgID_k_ESteamDatagramMsg_RouterPingRequest:
				relay.handleClientPingRequest(addr, body)
			case protos.ESteamDatagramMsgID_k_ESteamDatagramMsg_GameserverSessionRequest:
				var msg protos.CMsgSteamDatagramGameserverSessionRequest
				handleCtrlMsgNoSession(addr, &msg, relay.handleGameserverSessionRequest, body)

			case protos.ESteamDatagramMsgID_k_ESteamDatagramMsg_ConnectRequest:
				var msg protos.CMsgSteamDatagramConnectRequest
				relay.handleClientCtrlMessage(addr, &msg, msg.GetConnectionId, body)
			case protos.ESteamDatagramMsgID_k_ESteamDatagramMsg_Stats:
				var msg protos.CMsgSteamDatagramConnectionStatsClientToRouter
				relay.handleClientCtrlMessage(addr, &msg, msg.GetClientConnectionId, body)
			case protos.ESteamDatagramMsgID_k_ESteamDatagramMsg_ConnectionClosed:
				var msg protos.CMsgSteamDatagramConnectionClosed
				relay.handleClientCtrlMessage(addr, &msg, msg.GetFromConnectionId, body)
			case protos.ESteamDatagramMsgID_k_ESteamDatagramMsg_NoConnection:
				var msg protos.CMsgSteamDatagramNoConnection
				relay.handleClientCtrlMessage(addr, &msg, msg.GetFromConnectionId, body)

			default:
				fmt.Printf("unhandled control packet from client %s: %s\n", addr.String(), ctrl.String())
			}
		}
	case packetTypeFromClientHosted:
		relay.handleClientData(addr, cmd, body)
	default:
		fmt.Printf("unhandled cmd from client %s: %08b\n", addr.String(), cmd)
	}
}

func (relay *Relay) handleGameserverSessionRequest(clientAddr netip.AddrPort, msg *protos.CMsgSteamDatagramGameserverSessionRequest) {
	now := time.Now()

	ticket, err := ParseTicket(msg.GetTicket())
	if err != nil {
		fmt.Printf("failed to parse ticket: %s\n", err.Error())
		return
	}

	routingAddress, err := DecryptRoutingAddress(
		ticket.RoutingAddress,
		ticket.CaKeyID,
		ticket.ClientIdentity,
		ticket.ServerIdentity,
		relay.privateKey,
	)
	if err != nil {
		fmt.Printf("failed to decrypt routing address: %s\n", err.Error())
		return
	}

	var rawIP [4]byte
	binary.BigEndian.PutUint32(rawIP[:], routingAddress.GetIpv4())
	serverIP := netip.AddrFrom4(rawIP)
	serverAddr := netip.AddrPortFrom(serverIP, uint16(routingAddress.GetPort()))
	fmt.Println("server addr", serverAddr)

	session := relay.createSession(
		clientAddr,
		serverAddr,
		ticket.ClientIdentity,
		ticket.ServerIdentity,
		msg.GetClientConnectionId(),
		routingAddress.GetRoutingSecret(),
	)

	if session != nil {
		// it's okay to use stats here since we haven't started the receive loop yet
		relaySeq, _ := session.clientStats.consumeOutgoingSequence(now)
		var resp protos.CMsgSteamDatagramGameserverSessionEstablished
		resp.SetConnectionId(msg.GetClientConnectionId())
		resp.SetGameserverIdentityString(ticket.ServerIdentity)
		resp.SetSeqNumR2C(uint32(relaySeq))
		sendCtrlMsg(relay.clientConn, clientAddr, protos.ESteamDatagramMsgID_k_ESteamDatagramMsg_GameserverSessionEstablished, &resp)

		go session.recv()
	}
}

func (relay *Relay) handleClientData(addr netip.AddrPort, cmd uint8, packet []byte) {
	var clientHeader messageHeader
	var clientStats *protos.CMsgSteamDatagramConnectionStatsClientToRouter
	var timeSincePrevE2E time.Duration = -1
	var data []byte
	if cmd&packetFlagStats != 0 {
		// only allocate stats when we need to
		clientStats = new(protos.CMsgSteamDatagramConnectionStatsClientToRouter)
	}
	if err := readDataPacket(cmd, packet, &clientHeader, clientStats, &timeSincePrevE2E, &data); err != nil {
		fmt.Printf("failed to decode client data packet: %s\n", err.Error())
		return
	}

	// fmt.Printf("data packet from client %s (e2e %d relay %d) time since prev %s\n", addr.String(), header.E2ESeq, header.RelaySeq, timeSincePrev.String())

	session := relay.findClientSession(addr, clientHeader.SessionID)
	if session != nil {
		session.clientMessages <- clientDataMessage{
			header:           clientHeader,
			stats:            clientStats,
			timeSincePrevE2E: timeSincePrevE2E,
			body:             data,
		}
	}
	// FIXME: send noconnection
}

func (session *session) handleClientConnectRequest(msg *protos.CMsgSteamDatagramConnectRequest) {
	msg.SetGameserverRelaySessionId(session.serverSessionID)
	msg.SetConnectionId(session.clientConnectionID)
	msg.SetRoutingSecret(session.routingSecret)
	sendCtrlMsg(session.serverConn, session.serverAddr, protos.ESteamDatagramMsgID_k_ESteamDatagramMsg_ConnectRequest, msg)
}

func (session *session) handleClientStats(msg *protos.CMsgSteamDatagramConnectionStatsClientToRouter) {
	now := time.Now()
	if !session.clientStats.checkIncomingSequence(uint16(msg.GetSeqNumC2R())) {
		return
	}
	session.processClientStats(now, uint16(msg.GetSeqNumC2R()), msg)
	session.sendStatsToServer(now, msg)
}

func (session *session) handleClientConnectionClosed(msg *protos.CMsgSteamDatagramConnectionClosed) {
	msg.ClearQualityRelay()
	msg.SetFromRelaySessionId(session.serverSessionID)
	msg.SetFromIdentityString(session.clientIdentity)
	msg.SetRoutingSecret(session.routingSecret)
	sendCtrlMsg(session.serverConn, session.serverAddr, protos.ESteamDatagramMsgID_k_ESteamDatagramMsg_ConnectionClosed, msg)
}

func (session *session) handleClientNoConnection(msg *protos.CMsgSteamDatagramNoConnection) {
	msg.ClearQualityRelay()
	msg.SetFromRelaySessionId(session.serverSessionID)
	msg.SetFromIdentityString(session.clientIdentity)
	msg.SetRoutingSecret(session.routingSecret)
	sendCtrlMsg(session.serverConn, session.serverAddr, protos.ESteamDatagramMsgID_k_ESteamDatagramMsg_NoConnection, msg)
}

func (session *session) handleClientData(msg clientDataMessage) {
	now := time.Now()

	if !session.clientStats.checkIncomingSequence(msg.header.RelaySeq) {
		return
	}

	if msg.stats != nil {
		session.processClientStats(now, msg.header.RelaySeq, msg.stats)
	}

	forwardRelaySeq, timeSincePrevRelay := session.serverStats.consumeOutgoingSequence(now)
	serverHeader := messageHeader{
		E2ESeq:    msg.header.E2ESeq,
		RelaySeq:  forwardRelaySeq,
		SessionID: session.serverSessionID,
	}
	serverStats := session.writeServerStats(now, msg.stats)

	sendDataPacket(
		session.serverConn,
		session.serverAddr,
		// FIXME: real relays sometimes don't extend the session id. does this matter?
		newCmd(packetTypeFromRelay)|packetFlagExtendSession,
		serverHeader,
		serverStats,
		msg.timeSincePrevE2E,
		timeSincePrevRelay,
		msg.body,
	)
}
