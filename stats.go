package sdr

import (
	"mtobject/sdr/gen/protos"
	"time"
)

// constants for incoming packet duplicate/out-of-order detection
const (
	blockBitLog = 6                // 1<<6 == 64 bits
	blockBits   = 1 << blockBitLog // must be power of 2
	ringBlocks  = 1 << 7           // must be power of 2
	windowSize  = (ringBlocks - 1) * blockBits
	blockMask   = ringBlocks - 1
	bitMask     = blockBits - 1
	limit       = 0x4000
)

const (
	packedAckShift    int64         = 6
	maxPackedAckDelay int64         = 0xffff
	maxAckSendDelay   time.Duration = 10 * time.Millisecond
)

type stats struct {
	// When the last sequenced packet was sent
	lastSequenceSentAt time.Time
	// Next sequence number to send
	nextOutgoingSequence int64

	// Highest incoming sequence number we've seen so far
	highestIncomingSequence int64
	// Ring of previously received packets
	incomingSequenceRing [ringBlocks]uint64

	// Sorted array of acks that have been requested by the peer
	pendingAcks []ack
	// Has the peer requested that we acknowledge immediately
	receivedImmediateAckRequest bool
}

type ack struct {
	// Packed sequence number this ack request was received
	packedSeqNum uint16
	// When the ack request was received
	timestamp time.Time
}

func newStats() stats {
	return stats{
		nextOutgoingSequence: 1,
	}
}

// Consume the next outgoing sequence number and record the time we used it.
// Returns the wire sequence number and the time since the previous call to NextWithTime.
func (stats *stats) consumeOutgoingSequence(now time.Time) (uint16, time.Duration) {
	wire := uint16(stats.nextOutgoingSequence)
	stats.nextOutgoingSequence += 1

	since := now.Sub(stats.lastSequenceSentAt)
	stats.lastSequenceSentAt = now

	return wire, since
}

// Expands the packed sequence number and checks if it should be dropped, updating the internal state if not.
// stolen from wireguard-go
func (stats *stats) checkIncomingSequence(packed uint16) bool {
	gap := int16(packed - uint16(stats.highestIncomingSequence))
	counter := stats.highestIncomingSequence + int64(gap)
	if gap >= limit {
		// FIXME: kill the connection, not the entire process
		panic("sequence number jumped too far, cannot track")
	}

	indexBlock := counter >> blockBitLog
	if counter > stats.highestIncomingSequence { // move window forward
		current := stats.highestIncomingSequence >> blockBitLog
		// cap diff to clear the whole ring
		diff := min(indexBlock-current, ringBlocks)
		for i := current + 1; i <= current+diff; i++ {
			stats.incomingSequenceRing[i&blockMask] = 0
		}
		stats.highestIncomingSequence = counter
	} else if stats.highestIncomingSequence-counter > windowSize { // behind current window
		return false
	}
	// check and set bit
	indexBlock &= blockMask
	indexBit := counter & bitMask
	old := stats.incomingSequenceRing[indexBlock]
	new := old | 1<<indexBit
	stats.incomingSequenceRing[indexBlock] = new
	return old != new
}

func (stats *stats) requestOutgoingAck(packedSeqNum uint16, now time.Time) {
	// FIXME: limit max acks
	stats.pendingAcks = append(stats.pendingAcks, ack{packedSeqNum: packedSeqNum, timestamp: now})
}

func (stats *stats) consumeOutgoingAcks(now time.Time) []uint32 {
	acks := make([]uint32, len(stats.pendingAcks))
	for i, ack := range stats.pendingAcks {
		shiftedDelay := min(now.Sub(ack.timestamp).Microseconds()>>packedAckShift, maxPackedAckDelay) & 0xffff
		acks[i] = uint32(ack.packedSeqNum)<<16 | uint32(shiftedDelay)
	}

	// clear out elems but reuse cap
	stats.pendingAcks = stats.pendingAcks[:0]
	stats.receivedImmediateAckRequest = false

	return acks
}

func (stats *stats) havePendingAcks() bool {
	return len(stats.pendingAcks) > 0
}

func (stats *stats) updateSendStatsTimer(now time.Time) time.Duration {
	var nextSendTime time.Duration = -1
	if stats.receivedImmediateAckRequest {
		nextSendTime = 0
	}

	if len(stats.pendingAcks) > 0 {
		oldestTime := stats.pendingAcks[0].timestamp
		until := max(oldestTime.Add(maxAckSendDelay).Sub(now), 0)
		nextSendTime = min(nextSendTime, until)
	}

	return nextSendTime
}

func (session *session) processClientStats(
	now time.Time,
	packedRelaySeq uint16,
	stats *protos.CMsgSteamDatagramConnectionStatsClientToRouter,
) {
	needImmediateAck := stats.GetFlags()&uint32(protos.CMsgSteamDatagramConnectionStatsClientToRouter_ACK_REQUEST_IMMEDIATE) != 0
	session.clientStats.receivedImmediateAckRequest = session.clientStats.receivedImmediateAckRequest || needImmediateAck

	if stats.HasQualityRelay() || stats.GetFlags()&uint32(protos.CMsgSteamDatagramConnectionStatsClientToRouter_ACK_REQUEST_RELAY) != 0 {
		session.clientStats.requestOutgoingAck(packedRelaySeq, now)
	}

	nextStatsSendTime := session.clientStats.updateSendStatsTimer(now)
	if nextStatsSendTime >= 0 {
		session.sendClientStatsTimer.Reset(nextStatsSendTime)
	}
}

func (session *session) processServerStats(
	now time.Time,
	packedSeqNum uint16,
	stats *protos.CMsgSteamDatagramConnectionStatsServerToRouter,
) {
	needImmediateAck := stats.GetFlags()&uint32(protos.CMsgSteamDatagramConnectionStatsServerToRouter_ACK_REQUEST_IMMEDIATE) != 0
	session.serverStats.receivedImmediateAckRequest = session.serverStats.receivedImmediateAckRequest || needImmediateAck

	if stats.HasQualityRelay() || stats.GetFlags()&uint32(protos.CMsgSteamDatagramConnectionStatsServerToRouter_ACK_REQUEST_RELAY) != 0 {
		session.serverStats.requestOutgoingAck(packedSeqNum, now)
	}

	nextStatsSendTime := session.serverStats.updateSendStatsTimer(now)
	if nextStatsSendTime >= 0 {
		session.sendServerStatsTimer.Reset(nextStatsSendTime)
	}
}

func (session *session) writeClientStats(
	now time.Time,
	e2e *protos.CMsgSteamDatagramConnectionStatsServerToRouter,
) *protos.CMsgSteamDatagramConnectionStatsRouterToClient {
	needWrite := session.clientStats.havePendingAcks()
	needWrite = needWrite || e2e.HasSeqNumE2E()
	needWrite = needWrite || e2e.HasQualityE2E()
	needWrite = needWrite || e2e.GetFlags()&uint32(protos.CMsgSteamDatagramConnectionStatsServerToRouter_ACK_REQUEST_E2E) != 0
	if !needWrite {
		return nil
	}

	out := new(protos.CMsgSteamDatagramConnectionStatsRouterToClient)
	if e2e.HasSeqNumE2E() {
		out.SetSeqNumE2E(e2e.GetSeqNumE2E())
	}
	if e2e.HasQualityE2E() {
		out.SetQualityE2E(e2e.GetQualityE2E())
	}
	if e2e.GetFlags()&uint32(protos.CMsgSteamDatagramConnectionStatsServerToRouter_ACK_REQUEST_E2E) != 0 {
		out.SetFlags(out.GetFlags() | uint32(protos.CMsgSteamDatagramConnectionStatsRouterToClient_ACK_REQUEST_E2E))
	}
	if e2e.GetFlags()&uint32(protos.CMsgSteamDatagramConnectionStatsServerToRouter_ACK_REQUEST_IMMEDIATE) != 0 {
		out.SetFlags(out.GetFlags() | uint32(protos.CMsgSteamDatagramConnectionStatsRouterToClient_ACK_REQUEST_IMMEDIATE))
	}
	out.SetAckRelay(session.clientStats.consumeOutgoingAcks(now))

	return out
}

func (session *session) writeServerStats(
	now time.Time,
	e2e *protos.CMsgSteamDatagramConnectionStatsClientToRouter,
) *protos.CMsgSteamDatagramConnectionStatsRouterToServer {
	needWrite := session.serverStats.havePendingAcks()
	needWrite = needWrite || e2e.HasSeqNumE2E()
	needWrite = needWrite || e2e.HasQualityE2E()
	needWrite = needWrite || e2e.GetFlags()&uint32(protos.CMsgSteamDatagramConnectionStatsClientToRouter_ACK_REQUEST_E2E) != 0
	if !needWrite {
		return nil
	}

	out := new(protos.CMsgSteamDatagramConnectionStatsRouterToServer)
	if e2e.HasSeqNumE2E() {
		out.SetSeqNumE2E(e2e.GetSeqNumE2E())
	}
	if e2e.HasQualityE2E() {
		out.SetQualityE2E(e2e.GetQualityE2E())
	}
	if e2e.GetFlags()&uint32(protos.CMsgSteamDatagramConnectionStatsClientToRouter_ACK_REQUEST_E2E) != 0 {
		out.SetFlags(out.GetFlags() | uint32(protos.CMsgSteamDatagramConnectionStatsRouterToServer_ACK_REQUEST_E2E))
	}
	if e2e.GetFlags()&uint32(protos.CMsgSteamDatagramConnectionStatsClientToRouter_ACK_REQUEST_IMMEDIATE) != 0 {
		out.SetFlags(out.GetFlags() | uint32(protos.CMsgSteamDatagramConnectionStatsRouterToServer_ACK_REQUEST_IMMEDIATE))
	}
	out.SetAckRelay(session.serverStats.consumeOutgoingAcks(now))

	return out
}

func (session *session) sendStatsToClient(now time.Time, msg *protos.CMsgSteamDatagramConnectionStatsServerToRouter) {
	forwardMsg := session.writeClientStats(now, msg)
	if forwardMsg == nil {
		return
	}

	relaySeq, _ := session.clientStats.consumeOutgoingSequence(now)
	forwardMsg.SetSeqNumR2C(uint32(relaySeq))
	forwardMsg.SetClientConnectionId(session.clientConnectionID)

	sendCtrlMsg(session.clientConn, session.clientAddr, protos.ESteamDatagramMsgID_k_ESteamDatagramMsg_Stats, forwardMsg)
}

func (session *session) sendStatsToServer(now time.Time, msg *protos.CMsgSteamDatagramConnectionStatsClientToRouter) {
	forwardMsg := session.writeServerStats(now, msg)
	if forwardMsg == nil {
		return
	}

	relaySeq, _ := session.serverStats.consumeOutgoingSequence(now)
	forwardMsg.SetSeqNumR2S(uint32(relaySeq))
	forwardMsg.SetRelaySessionId(session.serverSessionID)
	forwardMsg.SetRoutingSecret(session.routingSecret)
	forwardMsg.SetClientConnectionId(session.clientConnectionID)
	forwardMsg.SetClientIdentityString(session.clientIdentity)
	// TODO
	// forwardMsg.SetServerConnectionId(...)

	sendCtrlMsg(session.serverConn, session.serverAddr, protos.ESteamDatagramMsgID_k_ESteamDatagramMsg_Stats, forwardMsg)
}
