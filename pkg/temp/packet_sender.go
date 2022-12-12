package temp

import (
	"ip/pkg/info"
)

/**
* This function will read from the packet sending channel and help to send out the necessary packets
* This goroutine is necessary because of the circular imports between the sockets, info and temp package
 */
func IpPacketSender(nodeInfo *info.NodeInfo) {
	for {
		packetSendRequest := <-nodeInfo.SendPacketChan // this should block if channel is empty
		SendPacket(
			nodeInfo,
			packetSendRequest.Dest,
			packetSendRequest.Proto,
			packetSendRequest.TTL,
			packetSendRequest.Payload,
			packetSendRequest.OverwriteSrcAddress,
		)
	}

}
