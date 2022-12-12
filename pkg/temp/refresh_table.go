package temp

import (
	"ip/pkg/info"
	"time"
	"log"
)

/*
* Function that keeps reading the entries in table and make sure they are fresh
* 
* @param nodeInfo: NodeInfo struct that contains information about the router
*/
func RefreshTable(nodeInfo *info.NodeInfo){

	refresh_rate, err := time.ParseDuration("12s")
	if err != nil {
		log.Fatalln("Parsing: ", err)
	}

	for {
		rt := nodeInfo.Table
		// get the current time
		currentTime := time.Now()
		entries := rt.Hops
		for k, entry := range entries {
			// for each entry, retrieve the last updated time
			entryLastUpdatedAt := entry.UpdatedAt
			// true only for self hop entries
			// as long as the node is up, self-hop entries remain
			if entryLastUpdatedAt.IsZero() {
				continue
			}
			elapsed := currentTime.Sub(entryLastUpdatedAt)
			// if it has been over 12s since the last update
			if elapsed > refresh_rate {
				rt.HopMtx.Lock()
				// remove
				delete(rt.Hops, k)
				rt.HopMtx.Unlock()
			}
		}
		time.Sleep(refresh_rate)
	}
}