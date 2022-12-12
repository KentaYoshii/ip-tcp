package temp

import (
	"fmt"
	"ip/pkg/info"
	"ip/pkg/packet"
)

/*
* Function that handles Ip Packet with Test Protocol
* In which case we just print it out to stdout
 */
func TestPacketHandler(new_packet *packet.IpPacket, nodeInfo *info.NodeInfo) {
	fmt.Println(new_packet.String())
	fmt.Print("> ")
}
