package socket

import (
	"ip/pkg/packet"
	"time"

	"github.com/google/netstack/tcpip/header"
)

/*
* Represents early arrival segments
 */
type EarlyArrival struct {
	StartSeq uint32
	EndSeq   uint32
	Data     []byte
	Flags    uint8
}

/*
* Handle incoming packets
 */
func (conn *VTCPConn) HandlePacket(tcpPacket *packet.TcpPacket) {
	// update sending fields
	ack := tcpPacket.Header.AckNum

	if conn.CCAlgo == "tahoe" {
		// HANDLE CASES FOR CONGESTION CONTROL
		oldestUnackedByte := conn.OldestUnackedByte
		if ack > oldestUnackedByte {
			newBytesAcknowledged := uint16(ack - oldestUnackedByte)
			conn.BytesAcknowledged += newBytesAcknowledged
			if conn.BytesAcknowledged >= conn.Cwnd {
				// FULL WINDOW ACKNOWLEDGE
				// CAN UPDATED CWND
				if conn.Cwnd < conn.Ssthresh {
					// SLOW START
					conn.Cwnd = conn.Cwnd * 2
				} else {
					// CONGESTION AVOIDANCE
					conn.Cwnd += MAX_TCP_PAYLOAD // increment by max segment size
				}
				conn.BytesAcknowledged = conn.BytesAcknowledged - conn.Cwnd // reset bytes acknowledged
				conn.DuplicateAckCount = 0                                  // reset duplicate acks
			}
		} else if ack == oldestUnackedByte {
			// POSSIBLE DUPLICATE ACK
			// CHECK ALL CONDITIONS
			if tcpPacket.Header.WindowSize == conn.ReceiverWindow && // no change in window size
				len(conn.SentSegmentsMetadata) > 0 && // outstanding segments present
				len(tcpPacket.Payload) == 0 && // empty packet
				tcpPacket.Header.Flags&header.TCPFlagFin == 0 && // SYNC and FIN bits off
				tcpPacket.Header.Flags&header.TCPFlagSyn == 0 {
				// DUPLICATE ACK
				conn.DuplicateAckCount += 1
				if conn.DuplicateAckCount == 3 {
					// FAST RETRANSMIT
					// we can consider this a loss, compute congestion window accordingly
					if conn.Cwnd < conn.Ssthresh {
						// SLOW START
						conn.Ssthresh = conn.Ssthresh / 2
					} else {
						// CONGESTION AVOIDANCE
						conn.Cwnd = conn.Cwnd / 2
					}

					// we don't want this to affect retransmission count or any other fields, so send here
					earliestUnackedSegment := conn.SentSegmentsMetadata[0]
					dataToSend := conn.SendBuffer.Get(earliestUnackedSegment.StartSeq, earliestUnackedSegment.EndSeq-earliestUnackedSegment.StartSeq)
					outgoingTcpPacket := conn.CreateTCPPacket(earliestUnackedSegment.StartSeq, dataToSend)
					conn.SendPacketChan <- &packet.SendPacketRequest{
						Dest:                packet.Int2ip(conn.RemoteIPAddress).String(),
						Proto:               packet.TCP_PROTOCOL,
						TTL:                 packet.DEFAULT_TTL,
						Payload:             outgoingTcpPacket.Marshal(),
						OverwriteSrcAddress: packet.Int2ip(conn.LocalIPAddress).String(),
					}
				}
			}
		}
	}

	if ack > conn.OldestUnackedByte {
		conn.SendingFieldsMtx.Lock()
		conn.OldestUnackedByte = ack
		conn.SendingFieldsMtx.Unlock()
		// ack was updated, remove outdated segment metadata
		for len(conn.SentSegmentsMetadata) > 0 {
			top := conn.SentSegmentsMetadata[0] // peek
			if ack >= top.EndSeq {
				// only update SRTT if the ack was in response to the segment
				if ack == top.EndSeq {
					// adjust SRTT based on RFC 793
					measuredRTT := float64(time.Since(top.SentTimestamp).Nanoseconds())
					if conn.SRTT == time.Second {
						// SRTT has not been set yet, set it as the value
						conn.SRTT = time.Duration(measuredRTT)
					} else {
						newSRTTNanoseconds := SRTT_ALPHA*float64(conn.SRTT.Nanoseconds()) + (1-SRTT_ALPHA)*measuredRTT
						conn.SRTT = time.Duration(newSRTTNanoseconds)
					}
				}

				conn.SentSegmentsMetadata = conn.SentSegmentsMetadata[1:] // deque
			} else {
				break // no need to continue
			}
		}
	}

	conn.ReceiverWindow = tcpPacket.Header.WindowSize
	packetSeq := tcpPacket.Header.SeqNum
	payloadLen := uint32(len(tcpPacket.Payload))

	// RESET RTO SINCE WE RECEIVED AN ACK
	// DOESN'T HAVE TO BE NEW ACK VALUE BECAUSE IT COULD BE ZERO WINDOW PROBING
	conn.RetransmissionCount = 1
	conn.SetRTO(conn.RetransmissionCount)

	if len(tcpPacket.Payload) == 0 {
		return
	}

	// passes accept conditions (not outdated, not too early, buffer has space)
	if (conn.AckN <= packetSeq && packetSeq < conn.AckN+conn.AdvertisedWindow()) ||
		(conn.AckN <= packetSeq+payloadLen-1 && packetSeq+payloadLen-1 < conn.AckN+conn.AdvertisedWindow()) {
		// update receiving fields
		if packetSeq <= conn.AckN {
			// HANDLE PARTIAL FILLS
			toAcceptStart := conn.AckN            // start is always next expected
			toAcceptEnd := packetSeq + payloadLen // constrained by window
			if toAcceptEnd-toAcceptStart > conn.AdvertisedWindow() {
				toAcceptEnd = toAcceptStart + conn.AdvertisedWindow()
			}
			toAcceptData := tcpPacket.Payload[toAcceptStart-packetSeq : toAcceptEnd-packetSeq]

			// update receive buffer + nxt
			conn.ReceiveBuffer.Put(toAcceptData, toAcceptStart)
			conn.AckN = toAcceptEnd

			// FILL CONTIGUOUS BYTES BASED ON EARLY ARRIVAL QUEUE
			// should we handle case where early arrival cannot fit in window?
			// this should never happen unless there is a case of shrinking window so not important to handle
			for len(conn.EarlyArrivalQueue) > 0 {
				top := conn.EarlyArrivalQueue[0]
				if top.StartSeq <= conn.AckN && top.EndSeq > conn.AckN { // contiguous + contains some unknown data
					// THIS ALSO HANDLES PARTIAL FILLS
					toInsertStart := conn.AckN
					dataToInsert := top.Data[toInsertStart-top.StartSeq:]
					conn.ReceiveBuffer.Put(dataToInsert, toInsertStart)
					conn.AckN = top.EndSeq
					conn.EarlyArrivalQueue = conn.EarlyArrivalQueue[1:] // deque
				} else if top.EndSeq <= conn.AckN { // outdated data
					conn.EarlyArrivalQueue = conn.EarlyArrivalQueue[1:] // deque
				} else {
					break
				}
			}
		} else {
			// EARLY ARRIVALS - insert into appropriate spot in queue
			earlyArrivalObject := EarlyArrival{
				StartSeq: packetSeq,
				EndSeq:   packetSeq + payloadLen,
				Data:     tcpPacket.Payload,
				Flags:    tcpPacket.Header.Flags,
			}
			inserted := false
			for i := 0; i < len(conn.EarlyArrivalQueue); i++ {
				existingObject := conn.EarlyArrivalQueue[i]
				if earlyArrivalObject.StartSeq < existingObject.StartSeq {
					// insert at index
					conn.EarlyArrivalQueue = append(conn.EarlyArrivalQueue[:i+1], conn.EarlyArrivalQueue[i:]...)
					conn.EarlyArrivalQueue[i] = earlyArrivalObject
					inserted = true
					break
				}
			}
			// insert at end if not inserted
			if !inserted {
				conn.EarlyArrivalQueue = append(conn.EarlyArrivalQueue, earlyArrivalObject)
			}
		}
	}

	// We always send ack even if we can't accept to packet (eg. full buffer)
	// To let other side know we are still connected

	outgoingTcpPacket := conn.CreateTCPPacket(conn.SeqN, []byte{})
	conn.SendPacketChan <- &packet.SendPacketRequest{
		Dest:                packet.Int2ip(conn.RemoteIPAddress).String(),
		Proto:               packet.TCP_PROTOCOL,
		TTL:                 packet.DEFAULT_TTL,
		Payload:             outgoingTcpPacket.Marshal(),
		OverwriteSrcAddress: packet.Int2ip(conn.LocalIPAddress).String(),
	}
}

/*
* unreadbytes
 */
func (conn *VTCPConn) UnreadBytes() uint32 {
	return conn.AckN - conn.LastByteRead - 1
}
