package socket

import (
	"ip/pkg/packet"
	"math"
	"sync"
	"time"

	"github.com/google/netstack/tcpip/header"
)

const (
	WINDOW_SIZE                  = 65535
	MIN_PORT                     = 1024
	MAX_PORT                     = 65535
	MAX_CLIENT_INFO_QUEUE        = 100 // buffer channel size
	MAX_TCP_PAYLOAD              = 1400 - packet.IP_HDR_LEN - packet.TCP_HDR_LEN
	MAX_RETRANSMIT_COUNT         = 3
	ZERO_WINDOW_PROBING_INTERVAL = time.Second
	SRTT_ALPHA                   = float64(0.9) // according to RFC 793
	SRTT_BETA                    = float64(1.3)
	MIN_RTO                      = 100 * time.Millisecond // I lowered this below 1s since we are in a loopback network
	MAX_RTO                      = 5 * time.Second
)

/*
* Struct for listen sockets
*
* LocalPort: port listen socket is listening on
* ClientInfoQueue: client info of clients that have connected but yet to be accepted. On accept, we will create a normal socket
* ClientInfoChan: buffered channel
 */
type VTCPListener struct {
	// We listen on all local IP addresses, so main struct only needs port
	SID             uint16
	LocalPort       uint16
	PacketChan      chan *packet.IpPacket
	ClientInfoQueue []SocketIdentifier
	ClientInfoChan  chan TCPClientInfo
	FinChan         chan bool
}

type TCPClientInfo struct {
	Identifier *SocketIdentifier
	Header     *header.TCPFields
}

/*
* Struct for normal sockets
*
 */
type VTCPConn struct {
	SID             uint16
	LocalIPAddress  uint32
	RemoteIPAddress uint32
	LocalPort       uint16
	RemotePort      uint16

	// CHANNELS
	PacketChan         chan *packet.TcpPacket         // this channel is primarily used for receving packets during handshake
	SendPacketChan     chan *packet.SendPacketRequest // send to this channel to send out IP packets
	TriggerSendChan    chan bool                      // trigger socket to check send buffer
	RetransmissionChan chan bool                      // trigger socket to check and retransmit if necessary
	FinChan            chan bool

	// Transmission Control Buffer (TCB) fields
	State         SocketState
	SendBuffer    *CircularBuffer
	ReceiveBuffer *CircularBuffer
	BufferSize    uint32 // max buffer size

	// FIELDS FOR TIMEOUTS
	SRTT                time.Duration // smoothed round trip time
	ReceiveTimeout      time.Time     // Time at which we will timeout
	RetransmissionCount int           // how many previous retransmissions (to calculate exponential backoff)

	// FIELDS FOR SENDING
	SeqN                 uint32       // NEXT SEQUENCE NUMBER TO BE SENT OUT (NXT)
	OldestUnackedByte    uint32       // OLDEST UNACKED SEGMENT (UNA)
	LastByteWritten      uint32       // LAST BYTE WRITTEN (LBW)
	ReceiverWindow       uint16       // window of other party (so we know how much we can send)
	SentSegmentsMetadata []Segment    // metadata of sent segments
	SendingFieldsMtx     sync.RWMutex // This is only to prevent race conditions between updating acks and checking if there is sufficient space to send during sending of large files

	// FIELDS FOR RECEIVING
	AckN              uint32         // ACK TO SEND - NEXT BYTE EXPECTED TO RECEIVE (NXT)
	LastByteRead      uint32         // last byte read by application (start of our buffer)
	EarlyArrivalQueue []EarlyArrival // Queue of non-contiguous early arrivals (ORDERED)

	//flags for sd
	WriteClose bool
	ReadClose  bool
	FINAckN    uint32

	//fields for termination
	TermStart time.Time
	IsTerm    bool

	// CONGESTION CONTROL
	CCAlgo            string // indicates congestion control algorithm. Either tahoe or empty string (none)
	Cwnd              uint16 // congestion window
	Ssthresh          uint16 // slow start threshold
	BytesAcknowledged uint16 // Used to know when to increase Cwnd according to RFC5681. reset when reached cwnd, and increment cwnd
	DuplicateAckCount int    // used to detect duplicate acks
}

//BufferSize - SendBufferUsed() = amount of stuff we can put in

/*
* This helper function helps to initialize a VTCPConnection
 */
func CreateVTCPConn(sid uint16, localIpAddress uint32, localPort uint16, remoteIpAddress uint32, remotePort uint16, state SocketState, isn uint32, ackn uint32, sendPacketChan chan *packet.SendPacketRequest) *VTCPConn {
	sockConn := &VTCPConn{
		SID:             sid,
		LocalIPAddress:  localIpAddress,
		LocalPort:       localPort,
		RemoteIPAddress: remoteIpAddress,
		RemotePort:      remotePort,
		// CHANNELS
		PacketChan:         make(chan *packet.TcpPacket),
		SendPacketChan:     sendPacketChan,
		TriggerSendChan:    make(chan bool), //stuff we have sent out yet
		RetransmissionChan: make(chan bool), //
		FinChan:            make(chan bool),
		// Transmission Control Buffer (TCB) fields
		State:         state,
		SendBuffer:    CreateCircularBuffer(WINDOW_SIZE),
		ReceiveBuffer: CreateCircularBuffer(WINDOW_SIZE),
		BufferSize:    WINDOW_SIZE,
		// FIELDS FOR TIMEOUTS
		SRTT:                time.Second, // when first reading observed, will replace this value, according to RFC
		ReceiveTimeout:      time.Now(),  // if ReceiveTimeout > current time, this means that either timeout is reached or the timer was not on (check segments)
		RetransmissionCount: 1,
		// FIELDS FOR SENDING
		SeqN:                 isn,
		OldestUnackedByte:    isn,
		LastByteWritten:      isn - 1,
		ReceiverWindow:       WINDOW_SIZE, // we assume they have max window size first but this will be updated during the handshake
		SentSegmentsMetadata: make([]Segment, 0),
		// FIELDS FOR RECEIVING
		AckN:              ackn,
		LastByteRead:      ackn - 1,
		EarlyArrivalQueue: make([]EarlyArrival, 0),
		// CC FIELDS
		CCAlgo:            "",
		Cwnd:              3 * MAX_TCP_PAYLOAD,  // initial window set according to rfc5681,
		Ssthresh:          30 * MAX_TCP_PAYLOAD, // set arbitrarily high according to rfc 5681
		BytesAcknowledged: 0,
		DuplicateAckCount: 0,
	}
	return sockConn
}

/*
* Advertised window
 */
func (conn *VTCPConn) AdvertisedWindow() uint32 {
	// if still in handshake, we do not have ack numbers yet
	if conn.State == SYN_SENT {
		return conn.BufferSize
	}

	return conn.BufferSize - ((conn.AckN - 1) - conn.LastByteRead)
}

/*
* This helper function creates an outgoing TCP packet for this socket
 */
func (sockConn *VTCPConn) CreateTCPPacket(seqN uint32, payload []byte) *packet.TcpPacket {
	tcpHdr := packet.ConstructTCPHeader(
		sockConn.LocalPort,
		sockConn.RemotePort,
		seqN,
		sockConn.AckN,
		string(sockConn.State),
		uint16(sockConn.AdvertisedWindow()),
	)
	localIp := packet.Int2ip(sockConn.LocalIPAddress)
	remoteIp := packet.Int2ip(sockConn.RemoteIPAddress)

	checksum := packet.ComputeTCPChecksum(tcpHdr, localIp, remoteIp, payload)
	tcpHdr.Checksum = checksum

	return &packet.TcpPacket{
		Header:  tcpHdr,
		Payload: payload,
	}
}

/*
* This function sets and turns on the RTO timer. Based on RFC793
*
* backoffCount: multiply the SRTT by the transmission count for exponential backoff
 */
func (sockConn *VTCPConn) SetRTO(backoffCount int) {

	rto := time.Duration(math.Floor(float64(sockConn.SRTT.Nanoseconds()) * SRTT_BETA))
	if MIN_RTO > rto {
		rto = MIN_RTO
	}
	if MAX_RTO < rto {
		rto = MAX_RTO
	}

	// set timeout
	sleepTime := time.Duration(backoffCount) * rto
	sockConn.ReceiveTimeout = time.Now().Add(sleepTime)

	// go to sleep and check timer
	go func(sockConn *VTCPConn, sleepTime time.Duration) {
		time.Sleep(sleepTime)
		// check if we need to trigger retransmission
		// criteria: timer was not reset, and there are unacked segments
		if (time.Now().Equal(sockConn.ReceiveTimeout) || time.Now().After(sockConn.ReceiveTimeout)) && len(sockConn.SentSegmentsMetadata) > 0 {
			sockConn.RetransmissionChan <- true
		}
	}(sockConn, sleepTime)

}
