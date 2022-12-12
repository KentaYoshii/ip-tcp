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
func ICMPPacketHandler(new_packet *packet.IpPacket, nodeInfo *info.NodeInfo) {
	nodeInfo.TracerouteChan <- new_packet.Header.Src.String()
}

/*
* Function that starts the trace route process
 */
func StartTraceroute(nodeInfo *info.NodeInfo, dest string) {
	// flush channel, make sure no residual data
	for len(nodeInfo.TracerouteChan) > 0 {
		<-nodeInfo.TracerouteChan
	}

	// find first hop
	externalInterface, err := nodeInfo.Table.Lookup(dest)
	if err != nil {
		nodeInfo.PrintChan <- err.Error() + "\n"
		return
	}

	nodeInfo.PrintChan <- fmt.Sprintf("Traceroute from %s to %s\n", externalInterface.RemoteIPAddress, dest)

	// maximum 30 times
	// TODO: implement timeout?
	i := 0
	for ; i <= 30; i++ {
		SendPacket(nodeInfo, dest, packet.ICMP_PROTOCOL, i, []byte{}, "")
		src := <-nodeInfo.TracerouteChan
		nodeInfo.PrintChan <- fmt.Sprintf("  %d %s\n", i+1, src)

		if src == dest {
			break
		}
	}

	nodeInfo.PrintChan <- fmt.Sprintf("  Traceroute finished in %d hops\n", i+1)
}
