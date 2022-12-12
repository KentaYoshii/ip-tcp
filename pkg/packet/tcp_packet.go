package packet

import (
	"encoding/binary"
	"net"

	"github.com/google/netstack/tcpip/header"
)

const (
	TCP_HDR_LEN        = header.TCPMinimumSize
	TCP_PSEUDO_HDR_LEN = 96
)

/*
* Struct for representing tcp packet
*
* Header: header.TCPFields to represent TCP header
* Payload: TCP packet payload
 */
type TcpPacket struct {
	Header  *header.TCPFields
	Payload []byte
}

/*
* Function that marshals TcpPacket struct into a byte slice
* The header bytes are followed by payload bytes
*
* @return bytes for payload
 */
func (tcpPacket *TcpPacket) Marshal() []byte {
	tcpHeaderBytes := make(header.TCP, TCP_HDR_LEN)
	tcpHeaderBytes.Encode(tcpPacket.Header)

	bytesToSend := make([]byte, 0, len(tcpHeaderBytes)+len(tcpPacket.Payload))
	bytesToSend = append(bytesToSend, tcpHeaderBytes...)
	bytesToSend = append(bytesToSend, []byte(tcpPacket.Payload)...)

	return bytesToSend
}

/*
* Function that unmarshals TcpPacket
*
* @return *TcpPacket: unmarshalled TcpPacket
 */
func UnmarshalTcpPacket(buffer []byte) (packet *TcpPacket) {
	tcpHeaderAndData := buffer
	tcpHdr := ParseTCPHeader(tcpHeaderAndData)
	tcpPayload := tcpHeaderAndData[tcpHdr.DataOffset:]
	return &TcpPacket{Header: tcpHdr, Payload: tcpPayload}
}

/*
* Function that computes the checksum for tcp packet
* 1. First we generate the pseudo header
 */
func ComputeTCPChecksum(tcpHdr *header.TCPFields,
	sourceIP net.IP, destIP net.IP, payload []byte) uint16 {

	// Fill in the pseudo header
	pseudoHeaderBytes := make([]byte, TCP_PSEUDO_HDR_LEN)
	pseudoHeaderBytes = append(pseudoHeaderBytes, sourceIP...) // 0..3
	pseudoHeaderBytes = append(pseudoHeaderBytes, destIP...)   // 4..7
	pseudoHeaderBytes[8] = 0
	pseudoHeaderBytes[9] = uint8(TCP_PROTOCOL)

	totalLength := TCP_HDR_LEN + len(payload)
	binary.BigEndian.PutUint16(pseudoHeaderBytes[10:12], uint16(totalLength))

	// Turn the TcpFields struct into a byte array
	headerBytes := header.TCP(make([]byte, TCP_HDR_LEN))
	headerBytes.Encode(tcpHdr)

	// Compute the checksum for each individual part and combine To combine the
	// checksums, we leverage the "initial value" argument of the netstack's
	// checksum package to carry over the value from the previous part
	pseudoHeaderChecksum := header.Checksum(pseudoHeaderBytes, 0)
	headerChecksum := header.Checksum(headerBytes, pseudoHeaderChecksum)
	fullChecksum := header.Checksum(payload, headerChecksum)

	// Return the inverse of the computed value,
	// which seems to be the convention of the checksum algorithm
	// in the netstack package's implementation
	return fullChecksum ^ 0xffff
}

/*
* Function that constructs the TCP Header for the packet we want to send
* (refer to section 3.1 of RFC9293)
*
* @param srcP : source port
* @param destP : destination port
* @param seqN : SEQ
* @param ackN : ACK
* @param flags : Flags
* @param win_sz : Window Size
* @return *header.TCPFields
 */
func ConstructTCPHeader(srcP uint16, destP uint16, seqN uint32, ackN uint32, state string, win_sz uint16) *header.TCPFields {
	newCTL := GenerateFlagForHandshake(state)
	tcpHdr := &header.TCPFields{
		SrcPort:       srcP,
		DstPort:       destP,
		SeqNum:        seqN,
		AckNum:        ackN,
		DataOffset:    20,
		Flags:         newCTL,
		WindowSize:    win_sz,
		Checksum:      0,
		UrgentPointer: 0,
	}
	return tcpHdr
}

/*
* Function that parses TCP Header from the byte slice
* (cpied from the ref repo)
*
* @param b : bytes from which we would like to extract TCP Header
* @return *header.TCPFields
 */
func ParseTCPHeader(b []byte) *header.TCPFields {
	td := header.TCP(b)
	return &header.TCPFields{
		SrcPort:    td.SourcePort(),
		DstPort:    td.DestinationPort(),
		SeqNum:     td.SequenceNumber(),
		AckNum:     td.AckNumber(),
		DataOffset: td.DataOffset(),
		Flags:      td.Flags(),
		WindowSize: td.WindowSize(),
		Checksum:   td.Checksum(),
	}
}

/*
* Helper function that helps genereate TCP Flags based on the state of that conn
*
* @param state : current state of the connection we want to generate the flag for
* @return header.TCP* : uint8 with relevant bits set
 */
func GenerateFlagForHandshake(state string) uint8 {
	switch state {
	//initiate a conn
	case "SYN_SENT":
		return header.TCPFlagSyn
		//server recieves Syn, respond with Syn, Ack
	case "SYN_RECEIVED":
		return header.TCPFlagSyn | header.TCPFlagAck
		//cli receives Syn, Ack and respond with Ack
	case "ESTABLISHED":
		return header.TCPFlagAck
	case "FIN_WAIT_1":
		return header.TCPFlagFin | header.TCPFlagAck
	case "LAST_ACK":
		return header.TCPFlagFin | header.TCPFlagAck
	case "CLOSE_WAIT":
		return header.TCPFlagAck
	case "TIME_WAIT":
		return header.TCPFlagAck
	}
	return 1
}
