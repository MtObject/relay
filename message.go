package sdr

import (
	"encoding/binary"
	"fmt"
	"mtobject/sdr/gen/protos"
	"net"
	"net/netip"
	"reflect"
	"time"

	"google.golang.org/protobuf/encoding/prototext"
	"google.golang.org/protobuf/proto"
)

const maxPacketLen = 1300

const maskPacketShift uint8 = 5

type packetType uint8

const (
	packetTypeCtrl             packetType = 0b000
	packetTypeFromRelay        packetType = 0b010
	packetTypeFromClientHosted packetType = 0b100
	packetTypeFromClientP2P    packetType = 0b101
	packetTypeFromServer       packetType = 0b110
)

const (
	packetFlagStats         = 1 << 0
	packetFlagTimeSincePrev = 1 << 1
	packetFlagExtendSession = 1 << 3
)

const timeSincePrevPackedShift int32 = 4

const messageHeaderLen = 8

type messageHeader struct {
	E2ESeq   uint16
	RelaySeq uint16
	// Equal to connection ID for client
	SessionID uint32
}

func getCmdType(cmd uint8) packetType {
	return packetType(cmd >> maskPacketShift)
}

func newCmd(cmd packetType) uint8 {
	return uint8(cmd) << maskPacketShift
}

type routerPingRequest struct {
	FlaggedVersion  uint8
	SdpingMagic     [6]byte
	ClientTimestamp uint32
	ClientCookie    uint32
	Always0         uint32
	ConfigRevision  uint32
	MaskedIP        uint32
	MaskedPort      uint16
	ProtocolVersion uint16
}

const routerPingLatencyFlagMask uint8 = 0x80

func sendCtrlMsg(conn *net.UDPConn, addr netip.AddrPort, msg protos.ESteamDatagramMsgID, body proto.Message) {
	encoded := make([]byte, 0, maxPacketLen)
	encoded = append(encoded, uint8(msg))
	encodedBody, err := proto.Marshal(body)
	if err != nil {
		fmt.Printf("failed to encode message: %s", err.Error())
		return
	}
	encoded = append(encoded, encodedBody...)

	// TODO: enforce maxPacketLen
	fmt.Printf("sending %s to %s: %s\n", msg.String(), addr.String(), body)

	_, _ = conn.WriteToUDPAddrPort(encoded, addr)
}

func handleCtrlMsgNoSession[Msg proto.Message](
	addr netip.AddrPort,
	msg Msg,
	callback func(netip.AddrPort, Msg),
	rawMsg []byte,
) {
	if err := proto.Unmarshal(rawMsg, proto.Message(msg)); err != nil {
		fmt.Printf("failed to decode ctrl packet: %s\n", err)
		return
	}

	fmt.Printf("received ctrl %s\n%s\n", msg.ProtoReflect().Descriptor().Name(), prototext.Format(msg))

	callback(addr, msg)
}

func sendDataPacket(
	conn *net.UDPConn,
	addr netip.AddrPort,

	cmd uint8,
	header messageHeader,
	stats proto.Message,
	timeSincePrevE2E time.Duration,
	timeSincePrevRelay time.Duration,
	body []byte,
) {
	if !reflect.ValueOf(stats).IsNil() {
		cmd |= packetFlagStats
	}

	if timeSincePrevE2E >= 0 && timeSincePrevRelay >= 0 {
		cmd |= packetFlagTimeSincePrev
	}

	// TODO: enforce maxPacketLen
	encoded := make([]byte, 0, maxPacketLen)
	encoded = append(encoded, cmd)
	encoded = binary.LittleEndian.AppendUint16(encoded, header.E2ESeq)
	encoded = binary.LittleEndian.AppendUint16(encoded, header.RelaySeq)
	encoded = binary.LittleEndian.AppendUint32(encoded, header.SessionID)

	if cmd&packetFlagStats != 0 {
		var err error

		statsLen := proto.Size(stats)
		options := proto.MarshalOptions{UseCachedSize: true}
		encoded = binary.AppendUvarint(encoded, uint64(statsLen))
		encoded, err = options.MarshalAppend(encoded, stats)
		if err != nil {
			fmt.Printf("failed to encode inline stats: %s", err.Error())
			return
		}

	}
	if cmd&packetFlagTimeSincePrev != 0 {
		packedE2E := uint16(timeSincePrevE2E.Microseconds() >> timeSincePrevPackedShift)
		packedRelay := uint16(timeSincePrevRelay.Microseconds() >> timeSincePrevPackedShift)

		encoded = binary.LittleEndian.AppendUint16(encoded, packedE2E)
		encoded = binary.LittleEndian.AppendUint16(encoded, packedRelay)
	}
	encoded = append(encoded, body...)

	_, _ = conn.WriteToUDPAddrPort(encoded, addr)
}

func readDataPacket(
	cmd uint8,
	packet []byte,

	header *messageHeader,
	inlineStats proto.Message,
	timeSincePrev *time.Duration,
	body *[]byte,
) error {
	if len(packet) < messageHeaderLen {
		return fmt.Errorf("data packet header missing")
	}

	header.E2ESeq = binary.LittleEndian.Uint16(packet)
	header.RelaySeq = binary.LittleEndian.Uint16(packet[2:])
	// TODO: support short session ID on server. we can figure this out based on cmd
	header.SessionID = binary.LittleEndian.Uint32(packet[4:])
	packet = packet[messageHeaderLen:]

	if cmd&packetFlagStats != 0 {
		statsLen, n := binary.Uvarint(packet)
		if n <= 0 {
			return fmt.Errorf("invalid stats blob varint")
		}
		packet = packet[n:]

		if statsLen > uint64(len(packet)) {
			return fmt.Errorf("stats blob too large")
		}

		if err := proto.Unmarshal(packet[:statsLen], inlineStats); err != nil {
			return err
		}
		packet = packet[statsLen:]
	}

	if cmd&packetFlagTimeSincePrev != 0 {
		if len(packet) < 2 {
			return fmt.Errorf("time since prev missing")
		}

		packedTimeSincePrev := binary.LittleEndian.Uint16(packet)
		packet = packet[2:]

		*timeSincePrev = time.Duration(int64(packedTimeSincePrev)<<timeSincePrevPackedShift) * time.Microsecond
	}

	*body = packet

	return nil
}
