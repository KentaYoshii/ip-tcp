package main

import (
	"fmt"
	"ip/pkg/info"
	"ip/pkg/packet"
	"ip/pkg/temp"
)

/*
* Function that gets called whenever a UDP Listener receives a packet
* It first checks the checksum to make sure packet is intact
* If it is then we determine whether it is meant for the src router or not
* If it is, we let one of our internal handlers handle it
* If not, we forward it to the next outgoing Interface
*
* @param nodeInfo: NodeInfo Struct representing this src router
* @param receivedPacket: packet we just received
 */
func handleIpPackets(nodeInfo *info.NodeInfo, receivedPacket *packet.IpPacket) {
	// validate checksum and ttl
	err := receivedPacket.ValidatePacket()
	if err != nil {
		if err.Error() == "IP Checksum" {
			fmt.Println("Packet dropped : IP Checksum did not match")
		} else if err.Error() == "TTL" {
			fmt.Println("Packet dropped : TTL reached 0")
			// send ICMP time limit exceeded
			temp.SendPacket(nodeInfo, receivedPacket.Header.Src.String(), packet.ICMP_PROTOCOL, packet.DEFAULT_TTL, []byte{}, "")
		} else if err.Error() == "TCP Checksum" {
			fmt.Println("Packet dropped : TCP Checksum did not match")
		} else {
			fmt.Println("Packet dropped : Remote Host not reachable")
		}
		fmt.Printf("> ")
		return
	}

	// check if this router is the Dst in the IPHeader field
	if nodeInfo.IsMyVIP(receivedPacket.Header.Dst.String()) {
		nodeInfo.InternalInterface.HandlePacket(receivedPacket, nodeInfo)
		return
	}

	// o.w. we forward this packet
	dstStr := receivedPacket.Header.Dst.String()
	extInterface, err := nodeInfo.Table.Lookup(dstStr)
	if err != nil {
		fmt.Printf("Packet dropped: %s\n", err.Error())
		fmt.Printf("\n> ")
		return
	}
	extInterface.ForwardPacket(receivedPacket)

}
