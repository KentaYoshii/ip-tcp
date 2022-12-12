package socket

import (
	"fmt"
	"ip/pkg/packet"
	"time"
)

type Segment struct {
	StartSeq      uint32
	EndSeq        uint32    // exclusive
	SentTimestamp time.Time // check if necessary
}

func (conn *VTCPConn) StartSender() {
	// read from trigger send chan
	for {
		select {
		case <-conn.RetransmissionChan:
			// retransmission is triggered
			// check criterias first (its ok to check again)
			if time.Now().Before(conn.ReceiveTimeout) || len(conn.SentSegmentsMetadata) == 0 {
				// IF RTO EXPIRES BUT THERE ARE NO UNACKNOWLEDGED SEGMENTS, WE CAN ASSUME ALL SEGMENTS WERE ACKNOWLEDGED
				continue // ignore
			}

			if conn.RetransmissionCount > MAX_RETRANSMIT_COUNT {
				// max retransmission count, sever connection
				fmt.Println("MAX RETRANSMISSION COUNT REACHED, STOPPING SENDER")
				conn.State = CLOSED
				return
			}

			if conn.CCAlgo == "tahoe" {
				// CONGESTION CONTROL
				if conn.Cwnd < conn.Ssthresh {
					// SLOW START
					conn.Ssthresh = conn.Ssthresh / 2
				} else {
					// CONGESTION AVOIDANCE
					conn.Cwnd = conn.Cwnd / 2
				}
			}

			// RETRANSMIT - only retransmit earliest unacked segment according to RFC 6298
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

			// RESET RETRANSMISSION TIMER
			conn.RetransmissionCount += 1
			conn.SetRTO(conn.RetransmissionCount)

			continue
		case <-conn.TriggerSendChan:
			// check if we have bytes to send
			if conn.BytesToBeSent() > 0 {
				if conn.ReceiverWindow > 0 {
					// send segments until available space is used up or no more bytes to send
					availableSpace := conn.ReceiverWindow - uint16(conn.InFlightBytes())

					if conn.CCAlgo == "tahoe" {
						// IF CONGESTION CONTROL IS USED, ADJUST AVAILABLE SPACE
						if conn.Cwnd < conn.ReceiverWindow {
							availableSpace = conn.Cwnd - uint16(conn.InFlightBytes())
						}
					}

					for availableSpace > 0 && conn.BytesToBeSent() > 0 {
						// determine how many bytes we can send in a segment
						var bytesToSend uint32

						// golang doesn't have min functions for uints :(
						if uint32(availableSpace) > conn.BytesToBeSent() {
							bytesToSend = conn.BytesToBeSent()
						} else {
							bytesToSend = uint32(availableSpace)
						}
						if MAX_TCP_PAYLOAD < bytesToSend {
							bytesToSend = MAX_TCP_PAYLOAD
						}

						// create segment and update window
						newSegment := Segment{
							StartSeq:      conn.SeqN,
							EndSeq:        conn.SeqN + bytesToSend,
							SentTimestamp: time.Now(),
						}
						conn.SentSegmentsMetadata = append(conn.SentSegmentsMetadata, newSegment)

						// send segment
						dataToSend := conn.SendBuffer.Get(conn.SeqN, bytesToSend)
						outgoingTcpPacket := conn.CreateTCPPacket(conn.SeqN, dataToSend)
						conn.SeqN += bytesToSend
						conn.SendPacketChan <- &packet.SendPacketRequest{
							Dest:                packet.Int2ip(conn.RemoteIPAddress).String(),
							Proto:               packet.TCP_PROTOCOL,
							TTL:                 packet.DEFAULT_TTL,
							Payload:             outgoingTcpPacket.Marshal(),
							OverwriteSrcAddress: packet.Int2ip(conn.LocalIPAddress).String(),
						}

						// recompute available space
						availableSpace = conn.ReceiverWindow - uint16(conn.InFlightBytes())
					}
				} else {
					// ZERO WINDOW PROBING
					// create 1 byte segment
					dataToSend := conn.SendBuffer.Get(conn.SeqN, 1)
					probingTcpPacket := conn.CreateTCPPacket(conn.SeqN, dataToSend)
					conn.SendPacketChan <- &packet.SendPacketRequest{
						Dest:                packet.Int2ip(conn.RemoteIPAddress).String(),
						Proto:               packet.TCP_PROTOCOL,
						TTL:                 packet.DEFAULT_TTL,
						Payload:             probingTcpPacket.Marshal(),
						OverwriteSrcAddress: packet.Int2ip(conn.LocalIPAddress).String(),
					}

					// set next probe interval
					go func() {
						time.Sleep(ZERO_WINDOW_PROBING_INTERVAL)
						conn.TriggerSendChan <- true
					}()
				}
			}

		}

	}
}

/*
* Get bytes in flight of a sending socket
* Ideally should match window size
 */
func (conn *VTCPConn) InFlightBytes() uint32 {
	return conn.SeqN - conn.OldestUnackedByte
}

/*
* Bytes to be sent
 */
func (conn *VTCPConn) BytesToBeSent() uint32 {
	return conn.LastByteWritten - conn.SeqN + 1
}

/*
* Amount of spaced used in send buffer
 */
func (conn *VTCPConn) SendBufferUsed() uint32 {
	conn.SendingFieldsMtx.RLock()
	defer conn.SendingFieldsMtx.RUnlock()
	return conn.LastByteWritten - conn.OldestUnackedByte + 1
}

// initial state of conn.LastByteWritten - conn.OldestUnackedByte = -1.
// But they are uint32 so it wraps around to the largest possible uint32 representation
func (conn *VTCPConn) TimeToFin() bool {
	if conn.LastByteWritten <= conn.OldestUnackedByte {
		return true
	} else {
		return false
	}
}

//sendbufferused == 0 *
