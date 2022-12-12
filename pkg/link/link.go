package link

import (
	"ip/pkg/packet"
	"log"
	"net"
	"sync"
)

/*
* Struct that represents a single interface in our network
*
* Id: unique identifier for the Interface
* UdpConn: net.UDPConn for the remote host
* LocalIPAddress: our src router's IPAddr for this interface
* RemoteIPAddress: remote router's IPAddr for this interface
* Activated: true if the link is up, false o.w.
 */
type ExternalInterface struct {
	Id              int
	HostConn        *net.UDPConn
	RemoteAddress   *net.UDPAddr
	LocalIPAddress  net.IP
	RemoteIPAddress net.IP
	Activated       bool
	LinkMtx         sync.RWMutex
}

/*
* Funciton that gets called when forwarding a packet to another router
*
* @param packet: IpPacket that we would like to send off
 */
func (ei *ExternalInterface) ForwardPacket(packet *packet.IpPacket) {
	bytesToSend := packet.Marshal()
	_, err := ei.HostConn.WriteToUDP(bytesToSend, ei.RemoteAddress)
	if err != nil {
		log.Panicln("Error writing to socket: ", err)
	}
}

/*
* Function that each router calls upon startup.
* Sends a RIP Packet with Command == 1, signifiying request for
* entries in their routing tables
 */
func (ei *ExternalInterface) RequestRouting() {
	new_rip_request := &packet.RipPacket{
		Command:     1,
		Num_entries: 0,
	}
	rip_bytes := new_rip_request.Marshal()
	ipHeader := packet.ConstructIPHeader(ei.LocalIPAddress.String(), ei.RemoteIPAddress.String(), len(rip_bytes), packet.RIP_PROTOCOL, 16)
	// compute init checksum
	headerBytes, err := ipHeader.Marshal()
	if err != nil {
		log.Fatalln("Error marshalling header:  ", err)
	}
	ipHeader.Checksum = int(packet.ComputeChecksum(headerBytes))
	// append rip_bytes to our IpPacket struct
	packet := &packet.IpPacket{
		Header:  ipHeader,
		Payload: rip_bytes,
	}
	bytesToSend := packet.Marshal()
	_, err = ei.HostConn.WriteToUDP(bytesToSend, ei.RemoteAddress)
	if err != nil {
		log.Panicln("Error writing to socket: ", err)
	}
}
