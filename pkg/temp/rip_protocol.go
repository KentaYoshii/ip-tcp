package temp

import (
	"fmt"
	"ip/pkg/info"
	"ip/pkg/packet"
	"ip/pkg/routing"
	"log"
	"time"
)

var nodeInfo *info.NodeInfo

/*
* Function that handles RIPPacket
* Depending on the Command number we handle it differently

* If Command == 1, then that is a request for sending entries

* If Command == 2, then the Entries field contain info about
* adjacent routers' entries so we update the src routers hops
*
* @param new_packet: RIP packet that we would like to handle
* @param nodeInfo: node info struct
 */
func RipPacketHandler(new_packet *packet.IpPacket, nodeInfo *info.NodeInfo) {
	ripPacket := packet.UnmarshalRipPacket(new_packet.Payload)
	// 1 == requesting routes...
	if ripPacket.Command == 1 {

	} else if ripPacket.Command == 2 {
		//2 == response routes...
		//update our hop entries with the received hop entries
		updatedEntries := nodeInfo.Table.UpdateHops(nodeInfo.LocalIPs, new_packet.Header.Src, ripPacket.Entries)
		//trigger neighbors of the updates
		if len(updatedEntries) != 0 {
			routing.TriggerNeighbors(nodeInfo.Table, updatedEntries)
		}
		// fmt.Println(ripPacket.String(new_packet.Header))
	} else {
		fmt.Println("Packet dropped: RIP packet with Invalid Command was sent")
		fmt.Printf("> ")
	}
}

func RipProtocolSender(myNodeInfo *info.NodeInfo) {
	nodeInfo = myNodeInfo
	duration, _ := time.ParseDuration("5s")

	for {
		rtable := nodeInfo.Table
		activeInts := nodeInfo.Table.GetActiveInterfaces()
		for _, exInt := range activeInts {
			rtable.HopMtx.RLock()
			outRIP := routing.ApplySHWPR(exInt, rtable.Hops)
			rtable.HopMtx.RUnlock()

			rip_bytes := outRIP.Marshal()
			hdr := packet.ConstructIPHeader(exInt.LocalIPAddress.String(), exInt.RemoteIPAddress.String(), len(rip_bytes), packet.RIP_PROTOCOL, packet.DEFAULT_TTL)
			hdrBytes, err := hdr.Marshal()
			if err != nil {
				log.Fatalln("Error marshalling header", err)
			}
			hdr.Checksum = int(packet.ComputeChecksum(hdrBytes))
			outIpPacket := &packet.IpPacket{
				Header:  hdr,
				Payload: rip_bytes,
			}
			bytesToSend := outIpPacket.Marshal()
			_, err = exInt.HostConn.WriteToUDP(bytesToSend, exInt.RemoteAddress)
			if err != nil {
				log.Panicln("Error writing to socket: ", err)
			}
		}
		time.Sleep(duration)
	}

}
