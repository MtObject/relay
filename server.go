package sdr

import (
	"fmt"
	"mtobject/sdr/gen/protos"
	"net/netip"
	"time"
)

func (relay *Relay) handleServerPackets() {
	for {
		buf := make([]byte, maxPacketLen)
		n, addr, err := relay.serverConn.ReadFromUDPAddrPort(buf[:])
		if err != nil {
			// FIXME: don't panic
			panic(err)
		}

		relay.handleServerPacket(addr, buf[:n])
	}
}

func (relay *Relay) handleServerPacket(addr netip.AddrPort, pkt []byte) {
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
			case protos.ESteamDatagramMsgID_k_ESteamDatagramMsg_ConnectOK:
				var msg protos.CMsgSteamDatagramConnectOK
				relay.handleServerCtrlMessage(addr, &msg, msg.GetGameserverRelaySessionId, body)
			case protos.ESteamDatagramMsgID_k_ESteamDatagramMsg_Stats:
				var msg protos.CMsgSteamDatagramConnectionStatsServerToRouter
				relay.handleServerCtrlMessage(addr, &msg, msg.GetRelaySessionId, body)
			case protos.ESteamDatagramMsgID_k_ESteamDatagramMsg_ConnectionClosed:
				var msg protos.CMsgSteamDatagramConnectionClosed
				relay.handleServerCtrlMessage(addr, &msg, msg.GetToRelaySessionId, body)
			case protos.ESteamDatagramMsgID_k_ESteamDatagramMsg_NoConnection:
				var msg protos.CMsgSteamDatagramNoConnection
				relay.handleServerCtrlMessage(addr, &msg, msg.GetToRelaySessionId, body)

			default:
				fmt.Printf("unhandled control packet from server %s: %s\n", addr.String(), ctrl.String())
			}
		}
	case packetTypeFromServer:
		relay.handleServerData(addr, cmd, body)
	default:
		fmt.Printf("unhandled cmd from server %s: %08b\n", addr.String(), cmd)
	}
}

func (relay *Relay) handleServerData(addr netip.AddrPort, cmd uint8, packet []byte) {
	if cmd&packetFlagExtendSession == 0 {
		fmt.Println("unextended session id not supported")
		return
	}

	var serverHeader messageHeader
	var serverStats *protos.CMsgSteamDatagramConnectionStatsServerToRouter
	var timeSincePrevE2E time.Duration = -1
	var body []byte
	if cmd&packetFlagStats != 0 {
		// only allocate stats when we need to
		serverStats = new(protos.CMsgSteamDatagramConnectionStatsServerToRouter)
	}
	if err := readDataPacket(cmd, packet, &serverHeader, serverStats, &timeSincePrevE2E, &body); err != nil {
		fmt.Printf("failed to decode data packet from server: %s\n", err.Error())
		return
	}

	// fmt.Printf("data packet from server %s (e2e %d relay %d) time since prev %s\n", addr.String(), header.E2ESeq, header.RelaySeq, timeSincePrev.String())

	session := relay.findServerSession(addr, serverHeader.SessionID)
	if session != nil {
		session.serverMessages <- serverDataMessage{
			header:           serverHeader,
			stats:            serverStats,
			timeSincePrevE2E: timeSincePrevE2E,
			body:             body,
		}
	}
	// FIXME: send noconnection
}

func (session *session) handleServerConnectOK(msg *protos.CMsgSteamDatagramConnectOK) {
	// client doesn't need to know this
	msg.ClearGameserverRelaySessionId()
	sendCtrlMsg(session.clientConn, session.clientAddr, protos.ESteamDatagramMsgID_k_ESteamDatagramMsg_ConnectOK, msg)
}

func (session *session) handleServerStats(msg *protos.CMsgSteamDatagramConnectionStatsServerToRouter) {
	now := time.Now()
	if !session.serverStats.checkIncomingSequence(uint16(msg.GetSeqNumS2R())) {
		return
	}
	session.processServerStats(now, uint16(msg.GetSeqNumS2R()), msg)
	session.sendStatsToClient(now, msg)
}

func (session *session) handleServerData(msg serverDataMessage) {
	now := time.Now()
	if !session.serverStats.checkIncomingSequence(msg.header.RelaySeq) {
		return
	}

	if msg.stats != nil {
		session.processServerStats(now, msg.header.RelaySeq, msg.stats)
	}

	forwardRelaySeq, timeSincePrevRelay := session.clientStats.consumeOutgoingSequence(now)
	clientHeader := messageHeader{
		E2ESeq:    uint16(msg.header.E2ESeq),
		RelaySeq:  forwardRelaySeq,
		SessionID: session.clientConnectionID,
	}
	clientStats := session.writeClientStats(now, msg.stats)

	sendDataPacket(
		session.clientConn,
		session.clientAddr,
		newCmd(packetTypeFromRelay),
		clientHeader,
		clientStats,
		msg.timeSincePrevE2E,
		timeSincePrevRelay,
		msg.body,
	)
}

func (session *session) handleServerConnectionClosed(msg *protos.CMsgSteamDatagramConnectionClosed) {
	// TODO: clear out fields client doesn't need to see
	msg.ClearQualityRelay()
	sendCtrlMsg(session.clientConn, session.clientAddr, protos.ESteamDatagramMsgID_k_ESteamDatagramMsg_ConnectionClosed, msg)
}

func (session *session) handleServerNoConnection(msg *protos.CMsgSteamDatagramNoConnection) {
	// TODO: clear out fields client doesn't need to see
	msg.ClearQualityRelay()
	sendCtrlMsg(session.clientConn, session.clientAddr, protos.ESteamDatagramMsgID_k_ESteamDatagramMsg_NoConnection, msg)
}
