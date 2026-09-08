package sdr

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"mtobject/sdr/gen/protos"
	"net/netip"
)

func packPopID(popid [4]byte) uint32 {
	return uint32(popid[3])<<24 |
		uint32(popid[0])<<16 |
		uint32(popid[1])<<8 |
		uint32(popid[2])
}

func (relay *Relay) handleClientPingRequest(addr netip.AddrPort, body []byte) {
	if len(body) < 99 {
		fmt.Printf("ping request is too small (%d bytes)\n", len(body))
		return
	}

	var msg routerPingRequest
	reader := bytes.NewReader(body)
	if err := binary.Read(reader, binary.LittleEndian, &msg); err != nil {
		panic("should never fail")
	}

	sendLatency, version :=
		msg.FlaggedVersion&routerPingLatencyFlagMask == 0,
		msg.FlaggedVersion & ^uint8(routerPingLatencyFlagMask)
	maxLen := 99
	if sendLatency {
		maxLen = 1299
	}

	if len(body) != maxLen {
		fmt.Printf("ping request is badly sized (%d bytes)\n", len(body))
		return
	}

	if version != 2 {
		fmt.Printf("bad version %d\n", version)
		return
	}

	if !bytes.Equal(msg.SdpingMagic[:], []byte("sdping")) {
		fmt.Printf("bad magic %s\n", msg.SdpingMagic)
		return
	}

	relay.sendClientPingResponse(addr, msg.ClientTimestamp, msg.ClientCookie, sendLatency)
}

func (relay *Relay) sendClientPingResponse(addr netip.AddrPort, clientTimestamp uint32, clientCookie uint32, sendLatency bool) {
	var msg protos.CMsgSteamDatagramRouterPingReply

	ipv4 := addr.Addr().As4()

	msg.SetClientTimestamp(clientTimestamp)
	msg.SetYourPublicIp(binary.LittleEndian.Uint32(ipv4[:]))
	msg.SetYourPublicPort(uint32(addr.Port()))
	msg.SetServerTime(99999)
	msg.SetChallenge(12345)
	msg.SetClientCookie(clientCookie)

	fmt.Println("send latency", sendLatency)

	if sendLatency {
		// we can always contact our own pop
		msg.SetLatencyDatacenterIds([]uint32{packPopID(relay.popid)})
		msg.SetLatencyPingMs([]uint32{0})
	} else {
		// ugh
		msg.SetFlags(uint32(protos.CMsgSteamDatagramRouterPingReply_FLAG_MAYBE_MORE_DATA_CENTERS) | uint32(protos.CMsgSteamDatagramRouterPingReply_FLAG_MAYBE_MORE_ALT_ADDRESSES))
	}

	// TODO: alt address
	// TODO: route exceptions
	// TODO: tos

	sendCtrlMsg(relay.clientConn, addr, protos.ESteamDatagramMsgID_k_ESteamDatagramMsg_RouterPingReply, &msg)
}
