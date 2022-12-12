package info

import (
	"fmt"
	"ip/pkg/packet"
	"ip/pkg/routing"
	"ip/pkg/socket"
	"net"
	"sort"
	"sync"
	"github.com/gookit/color"
)

/*
* Info Struct that stores info about our own router
*
* Table: RoutingTable struct for this router
* SocketTable: SocketTable struct for this node
* Conn: Listening UDPConn for this router
* LocalIPs: map of local ip string addresses
*
* Channels:
* PrintChan: channel for printing to standard out (ensures synchronity in printing)
* TracerouteChan: channel for sending src address
* IpPacketChan: channel for incoming IP packets
* SendIpPacketChan: channel for sending outgoing IP packets
 */
type NodeInfo struct {
	Table             *routing.RoutingTable
	SocketTable       *socket.SocketTable
	Conn              *net.UDPConn
	LocalIPs          map[string]bool
	InternalInterface *InternalInterface

	PrintChan       chan string
	TracerouteChan  chan string
	IpPacketChan    chan *packet.IpPacket
	SendPacketChan  chan *packet.SendPacketRequest
	SocketWaitGroup sync.WaitGroup
}

/*
* Function that checks if input IP Address is one of its own VIPs
*
* @param toCheck: vip we want to check
* @param net.IP: if it is, return the VIP, nil o.w
 */
func (ni *NodeInfo) IsMyVIP(toCheck string) bool {
	_, ok := ni.LocalIPs[toCheck]
	return ok
}

/*
* Function that prints the socket table in ascending order with respect to socket ID
 */
func (ni NodeInfo) PrintSocketTable() string {
	outString := fmt.Sprintf("%6s    %6s     %6s     %6s     %6s     %6s	 %6s\n", 
	"socket", 
	"local-addr", 
	"port", 
	"dest-addr", 
	"port",
	"status",
	"cc-algo",
	)
	outString += "---------------------------------------------------------------------------------\n"
	allSocksMap := make(map[uint16]string)
	zero := "0.0.0.0"
	//get all the listening sockets
	for sid, lisConn := range ni.SocketTable.ListeningSocks {
		curString := color.Cyan.Sprintf("%6d       %6s     %6d      %6s      %6d     %6s       %6s\n", sid, zero, lisConn.LocalPort, zero, 0, "LISTEN", "None")
		allSocksMap[sid] = curString
	}
	//get all the connecting sockets
	for sid, conConn := range ni.SocketTable.SockTable {
		stateString := ""
		if conConn.State == socket.ESTABLISHED {
			stateString = "ESTAB"
		} else if conConn.State == socket.CLOSE_WAIT {
			stateString = "CLOSE_W"
		} else {
			stateString = string(conConn.State)
		}
		curString := fmt.Sprintf(
			"%6d   %6s     %6d  %6s      %6d     %6s       %6s\n",
			sid,
			packet.Int2ip(conConn.LocalIPAddress).String(),
			conConn.LocalPort,
			packet.Int2ip(conConn.RemoteIPAddress).String(),
			conConn.RemotePort,
			stateString,
			conConn.CCAlgo,
		)
		allSocksMap[sid] = curString
	}
	//sort on socket ID
	keys := make([]int, 0, len(allSocksMap))
	for k := range allSocksMap {
		keys = append(keys, int(k))
	}
	sort.Ints(keys)
	for _, k := range keys {
		outString += allSocksMap[uint16(k)]
	}

	return outString
}

/*
*  Helper that checks if the port is already used by one of our listening sock
 */
func (ni *NodeInfo) IsPortBound(port2Check uint16) bool {
	for _, listener := range ni.SocketTable.ListeningSocks {
		if listener.LocalPort == port2Check {
			return true
		}
	}
	return false
}

/*
* Function type for handlers
 */
type HandlerFn func(*packet.IpPacket, *NodeInfo)

/*
* Struct that holds multiple handler funcs
*
* Handlers: map from protocol to its corresponding handler functions
 */
type InternalInterface struct {
	Handlers map[int]HandlerFn
}

/*
* Function that takes in a packet and handles it accordingly by
* invoking its corresponding handler func
*
* @param packet: IpPacket that we would like to handle
 */
func (ii *InternalInterface) HandlePacket(packet *packet.IpPacket, nodeInfo *NodeInfo) {
	protocol := packet.Header.Protocol
	if handler, ok := ii.Handlers[protocol]; ok {
		handler(packet, nodeInfo)
		return
	}
}

/*
* Function that adds <protocol, handler> pair to our InternalInterface
*
* @param protocol: 0 or 200
* @param handler: handler for either protocol 0 or 200
 */
func (ii *InternalInterface) RegisterHandler(protocol int, handler HandlerFn) {
	ii.Handlers[protocol] = handler
}
