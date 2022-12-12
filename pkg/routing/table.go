package routing

import (
	"fmt"
	"ip/pkg/link"
	"ip/pkg/packet"
	"log"
	"net"
	"sync"
	"time"
)

const (
	HOP_EXPIRATION_SECONDS = 12
)

/*
* Our way of representing this router's Routing Table
*
* Interfaces: map from remoteAddress to the interface that connects to it
* Hops: map from remoteAddress to Hop struct
* HopMtx: sync.RWMutex for updating hop information
 */
type RoutingTable struct {
	Interfaces map[string]*link.ExternalInterface
	Hops       map[string]*Hop
	HopMtx     sync.RWMutex
}

/*
* Hop represents a single entry in our Forwaridng Table
*
* Data: Contains information about the Hop
* UpdatedAt: time.Time. Used to determine the particular time at which the entry was updated
 */
type Hop struct {
	Data      *packet.HopData
	UpdatedAt time.Time
	Sender    uint32 //4b
}

/*
* Function that determines if hop has expired. I.e. Last updated more than 12 seconds ago
*
* @return bool: indicating if hop has expired
 */

func (hop *Hop) isExpired() bool {
	timeLapsed := time.Since(hop.UpdatedAt)
	return timeLapsed.Seconds() > HOP_EXPIRATION_SECONDS
}

/*
* Function that determins which interface it wants to relay the packet to
*
* (1) First we check for any activated interfaces which match the destination address
* (2) If we could not find one, we check the hops table
* (3) We then return the interface that connects to the nextHop
*
* @param destIpAddr : final destination router
* @return link.LinkInterface, error : our next interface in the forwarding process, error
 */
func (rt *RoutingTable) Lookup(destIpAddr string) (*link.ExternalInterface, error) {
	// check interfaces
	if extInterface, ok := rt.Interfaces[destIpAddr]; ok {
		if extInterface.Activated {
			return extInterface, nil
		}
	}

	// check hops if no interface found
	// if interface found, but not activated, we should still check hops
	rt.HopMtx.RLock()
	defer rt.HopMtx.RUnlock()
	if nextHop, ok := rt.Hops[destIpAddr]; ok {
		if !nextHop.isExpired() && nextHop.Data.Cost < packet.MAX_HOP_COST {
			// only use if next hop not expired and reachable (cost less than infinity)
			// check interfaces again
			sender := packet.Int2ip(nextHop.Sender).String()
			if extInterface, ok := rt.Interfaces[sender]; ok {
				if extInterface.Activated {
					return extInterface, nil
				}
			}
		}
	}

	return nil, fmt.Errorf("no path to %s", destIpAddr)
}

/*
* Function that takes in an Interface and slice of HopData and returns RipPacket to be sent to that
* interface with Split Horizon with Poisoned Reverse applied
*
* @param exInt: the External Interface we will be forwarding Hop entries to
* @param entries: the entries we want to filter
 */
func ApplySHWPR(exInt *link.ExternalInterface, entries map[string]*Hop) *packet.RipPacket {
	hopToSend := make([]*packet.HopData, 0)
	remoteHostAddrInt, err := packet.Ip2int(exInt.RemoteIPAddress)
	if err != nil {
		log.Fatalln("Converting ip to int: ", err)
	}
	for _, entry := range entries {
		// note: we can send hops with infinite cost to update neighbors that we are no longer able to reach a node

		// if we did get the entry from the remoteHost to begin with
		if remoteHostAddrInt == entry.Sender {
			newEntry := &packet.HopData{
				Cost:    packet.MAX_HOP_COST, // inf
				Address: entry.Data.Address,
				Mask:    packet.MAX_UINT32,
			}
			hopToSend = append(hopToSend, newEntry)
		} else {
			hopToSend = append(hopToSend, entry.Data)
		}
	}

	outRIPPacket := &packet.RipPacket{
		Command:     2,
		Num_entries: uint16(len(hopToSend)),
		Entries:     hopToSend,
	}
	return outRIPPacket
}

func TriggerNeighbors(rt *RoutingTable, newEntries map[string]*Hop) {
	activeInts := rt.GetActiveInterfaces()
	for _, exInt := range activeInts {
		outRIP := ApplySHWPR(exInt, newEntries)
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
}

func (rt *RoutingTable) ActivateInterface(id int) error {
	retInt := rt.GetInterface(id)
	if retInt == nil {
		return fmt.Errorf("error: Interface [%d] not found", id)
	}
	if retInt.Activated {
		return fmt.Errorf("error: Interface [%d] already up", id)
	}
	retInt.LinkMtx.Lock()
	defer retInt.LinkMtx.Unlock() // prevents activation and deactivation from happening concurrently
	retInt.Activated = true

	rt.HopMtx.Lock()
	defer rt.HopMtx.Unlock()
	// (1) restore hop to local ip address
	// someone could have sent us a replacement hop so we need to replace it
	localIntIp, err := packet.Ip2int(retInt.LocalIPAddress)
	if err != nil {
		log.Fatalln("Converting IPv4 to int32:", err)
	}
	localHop := &Hop{
		Data: &packet.HopData{
			Cost:    0,
			Address: localIntIp,
			Mask:    packet.MAX_UINT32,
		},
		Sender: localIntIp,
	}
	rt.Hops[retInt.LocalIPAddress.String()] = localHop

	// (2) restore hop to neighbor
	neighborIntIp, err := packet.Ip2int(retInt.RemoteIPAddress)
	if err != nil {
		log.Fatalln("Converting IPv4 to int32:", err)
	}
	neighborHop := &Hop{
		Data: &packet.HopData{
			Cost:    1,
			Address: neighborIntIp,
			Mask:    packet.MAX_UINT32,
		},
		Sender: neighborIntIp,
	}
	rt.Hops[retInt.RemoteIPAddress.String()] = neighborHop

	// (3) request routing from previously deactivated neighbor
	retInt.RequestRouting()

	return nil
}

func (rt *RoutingTable) DeactivateInterface(id int) error {
	retInt := rt.GetInterface(id)
	if retInt == nil {
		return fmt.Errorf("error: Interface [%d] not found", id)
	}
	if !retInt.Activated {
		return fmt.Errorf("error: Interface [%d] already down", id)
	}

	retInt.LinkMtx.Lock()
	defer retInt.LinkMtx.Unlock() // prevents activation and deactivation from happening concurrently
	retInt.Activated = false

	rt.HopMtx.Lock()
	defer rt.HopMtx.Unlock()

	// keep track of removed entries
	updatedHops := make(map[string]*Hop)

	// (1) Remove hop for local ip of deactivated interface
	localHop := rt.Hops[retInt.LocalIPAddress.String()]
	localHop.Data.Cost = packet.MAX_HOP_COST
	updatedHops[retInt.LocalIPAddress.String()] = localHop
	delete(rt.Hops, retInt.LocalIPAddress.String())

	// (2) Find and remove all hops where next hop is deactivated interface
	for dest, hop := range rt.Hops {
		ip := packet.Int2ip(hop.Sender)
		if ip.String() == retInt.RemoteIPAddress.String() {
			// remove
			hop.Data.Cost = packet.MAX_HOP_COST
			updatedHops[dest] = hop
			delete(rt.Hops, dest)
		}
	}

	// (3) Update neighbors of removed entries
	TriggerNeighbors(rt, updatedHops)

	return nil
}

/*
* Function that retrieves an interface with matching id
*
* @param id: the interface id for lookup
 */
func (rt *RoutingTable) GetInterface(id int) *link.ExternalInterface {
	for _, inT := range rt.Interfaces {
		if id == inT.Id {
			return inT
		}
	}
	return nil
}

/*
* Function that retrievs all the active interfaces for that table
 */
func (rt *RoutingTable) GetActiveInterfaces() []*link.ExternalInterface {
	activeInts := make([]*link.ExternalInterface, 0)
	for _, inT := range rt.Interfaces {
		if inT.Activated {
			activeInts = append(activeInts, inT)
		}
	}
	return activeInts
}

/*
* Function that updates our HopTable
* We check for 5 cases which observes Distance Vector Algorithm
*
* For every <dest, next_hop_new, cost_new> we receive via RIPPacket
*
  - Case 1: if dest is not in rt -> add
  - Case 2: if dest exists with <dest, next_hop_cur, cost_cur>
  - if cost < cost_old
  - update the entry to <dest, next_hop, cost>
  - Case 3: if dest exists with <dest, next_hop_cur, cost_cur>
    if next_hop_cur == next_hop_new && cost_new > cost_cur
    update the entry to <dest, next_hop_cur, cost_new>
  - Case 4: if dest exists with identical entry
  - do nothing
  - Case 5: if dest exists
  - if next_hop_cur != next_hop_new && cost_new > cost_cur
  - do nothing

*
* For Case 1~4, we refresh the timer
*/
func (rt *RoutingTable) UpdateHops(myVIPs map[string]bool, cameFromAddr net.IP, entries []*packet.HopData) map[string]*Hop {
	updatedEntries := make(map[string]*Hop, 0)
	currentEntries := rt.Hops

	// first we check if interface is activated, if interface doesn't exist or is deactivated, we shouldn't update hops using it
	intf, ok := rt.Interfaces[cameFromAddr.String()]
	if !ok || !intf.Activated {
		return updatedEntries
	}

	cameFromAddrInt, err := packet.Ip2int(cameFromAddr)
	if err != nil {
		log.Fatalln("Converting IP to int")
	}
	for _, entry := range entries {
		curDestAddrInt := entry.Address
		curDestAddrStr := packet.Int2ip(curDestAddrInt).String()

		// check if the destination is one of my interfaces
		if _, ok := myVIPs[curDestAddrStr]; ok {
			// neighbors can never provide a lower cost hop
			continue
		}

		// all cases will create same hop data if we update
		newCost := entry.Cost + 1
		newHopData := &packet.HopData{
			Address: curDestAddrInt,
			Cost:    newCost,
			Mask:    packet.MAX_UINT32,
		}
		newHop := &Hop{
			Data:      newHopData,
			Sender:    cameFromAddrInt,
			UpdatedAt: time.Now(),
		}

		curEntry, ok := currentEntries[curDestAddrStr]

		// Destination not currently in rt
		// OR entry exists but expired
		if !ok || curEntry.isExpired() {
			// Case 1: Destination not currently in rt

			// do not add if unreachable
			if entry.Cost == packet.MAX_HOP_COST {
				continue
			}

			// add new entry to the table
			rt.HopMtx.Lock()
			currentEntries[curDestAddrStr] = newHop
			rt.HopMtx.Unlock()

			// add to updated entries
			updatedEntries[curDestAddrStr] = newHop
			continue
		} else {
			curDestEntry := curEntry.Data
			curCost := curDestEntry.Cost
			if newCost < curCost {
				// Case 2: lower cost than existing entry
				// update table entry
				rt.HopMtx.Lock()
				currentEntries[curDestAddrStr] = newHop
				rt.HopMtx.Unlock()

				// add to updated entries
				updatedEntries[curDestAddrStr] = newHop
				continue
			}

			if curEntry.Sender == cameFromAddrInt {
				if newCost > curCost {
					// Case 3: Same hop but higher cost
					rt.HopMtx.Lock()
					if newCost >= packet.MAX_HOP_COST {
						// if new cost equal or greater than max hop cost, we are informed that this host is now unreachable
						delete(currentEntries, curDestAddrStr)
					} else {
						currentEntries[curDestAddrStr] = newHop
					}
					rt.HopMtx.Unlock()

					// add to updated entries
					updatedEntries[curDestAddrStr] = newHop
					continue
				} else {
					//Case 4: Same hop, same cost
					// refresh timer
					currentEntries[curDestAddrStr].UpdatedAt = time.Now()
					continue
				}
			} else {
				//Case 5: Higher cost from different hop, ignore
				continue
			}
		}
	}
	return updatedEntries
}

/*
* Function that gets all the hop entries in our Routing Table
*
* @return []*packet.HopData : hop entries
 */
func (rt *RoutingTable) GetAllHops() []*packet.HopData {
	retEntries := make([]*packet.HopData, 0)
	for _, hop := range rt.Hops {
		retEntries = append(retEntries, hop.Data)
	}
	return retEntries
}

/*
* Function that gets all the outgoing hop entries in our Routing Table
 */
func (rt *RoutingTable) GetAllExtHops() []*packet.HopData {
	retEntries := make([]*packet.HopData, 0)
	for _, hop := range rt.Hops {
		if hop.Data.Cost == 0 {
			continue
		}
		retEntries = append(retEntries, hop.Data)
	}
	return retEntries
}

/*
* Function that gets called once in main upon startup
* This will initialize the routing table with the initial information about
* the router's adjacent routers
*
* @param extInterfaces : interfaces slice that we would like to populate
*
* @return *RoutingTable : forwarding table for this particular router
 */
func CreateRoutingTable(extInterfaces []*link.ExternalInterface) *RoutingTable {

	rt := &RoutingTable{
		Interfaces: make(map[string]*link.ExternalInterface),
		Hops:       make(map[string]*Hop),
	}

	for _, extInterface := range extInterfaces {
		curRemoteAddr := extInterface.RemoteIPAddress.String()
		// if we are A, and the interface connects A <-> B,
		// this will be a mapping from B -> Interface(A <-> B)
		rt.Interfaces[curRemoteAddr] = extInterface
		intIp, err := packet.Ip2int(extInterface.RemoteIPAddress)
		if err != nil {
			log.Fatalln("Converting IPv4 to int32:", err)
		}
		newHopData := &packet.HopData{
			Cost:    1,
			Address: intIp,
			Mask:    packet.MAX_UINT32, //uint32 with all bits set
		}
		// if we have A <-> B <-> C
		// In the A's hop table,
		// C -> {{2 (Cost), C's ipaddr (Address), mask (Mask), B's ipaddr (Sender/next hop)}, time it was updated}
		newHop := &Hop{
			Data:   newHopData,
			Sender: intIp, //since adj node
		}

		rt.HopMtx.Lock()
		rt.Hops[curRemoteAddr] = newHop
		rt.HopMtx.Unlock()
	}

	return rt
}
