package temp

import (
	"ip/pkg/packet"
	"log"
	"net"
)

const (
	MAX_PACKET_SIZE = 1400
)

/*
* Function that binds the port and listens for incoming packet traffic.
* If it was meant for myself, handle that accordingly, else forward it to other routers
*
* @param conn : UDP connection to read from
* @param ipPacketChannel : channel to which we will send out the packets received with proto == 0
 */
func HandleUdpListener(conn *net.UDPConn, ipPacketChannel chan *packet.IpPacket) {

	for {
		buffer := make([]byte, MAX_PACKET_SIZE)
		_, _, err := conn.ReadFromUDP(buffer)
		if err != nil {
			log.Panicln("Error reading from UDP socket ", err)
		}

		// Marshal the received byte array into an IP packet
		packet := packet.UnmarshalIpPacket(buffer)
		// send to channel
		ipPacketChannel <- packet
	}
}
