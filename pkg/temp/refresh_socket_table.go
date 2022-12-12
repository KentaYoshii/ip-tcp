package temp

import (
	"ip/pkg/info"
	"time"
)

/*
* Function that keeps reading the entries in table and make sure they are fresh
*
* @param nodeInfo: NodeInfo struct that contains information about the router
 */
func RefreshSocketTable(nodeInfo *info.NodeInfo) {

	for {
		st := nodeInfo.SocketTable.SockTable
		toDelete := make([]uint16, 0)
		for _, socket := range st {
			if string(socket.State) == "CLOSED" {
				toDelete = append(toDelete, socket.SID)
			}
		}
		for _, curSID := range toDelete {
			delete(st, curSID)
		}
		time.Sleep(time.Second * 1)
	}
}
  