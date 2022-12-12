package main

import (
	"bufio"
	"fmt"
	"ip/pkg/info"
	"ip/pkg/link"
	"ip/pkg/packet"
	"ip/pkg/routing"
	"ip/pkg/socket"
	"ip/pkg/temp"
	"log"
	"net"
	"os"
	"strings"
	"time"
)

/*
* Function that Dials the adjacent routers. We do this for
* each adjacent router for our source router
*
* @param remoteUdpPort: UDP port we want to dial
* @return *net.UDPConn: Connection socket bound to the udp port
 */
func resolveNeighbor(address string, remoteUdpPort string) *net.UDPAddr {
	addrString := fmt.Sprintf("%s:%s", address, remoteUdpPort)
	remoteAddr, err := net.ResolveUDPAddr("udp4", addrString)
	if err != nil {
		log.Panicln("Error resolving address:  ", err)
	}

	fmt.Printf("Connected with %s:%d\n",
		remoteAddr.IP.String(), remoteAddr.Port)

	return remoteAddr
}

/*
* Function that gets called once upon the startup of the node
* RIP packet with Command set to 0 is set to all its adjacent nodes
* to request routes info
 */
func requestRoutes(extInterfaces []*link.ExternalInterface) {
	for _, extInterface := range extInterfaces {
		extInterface.RequestRouting()
	}
}

/*
  - Parses the .lnx file and populate the extInterfaces slice
  - which contains all the connecting interfaces for this router
  - e.g. Interface connecting A -> B
  - ExternalInterface {
    Id : 0 // unique identifer for the interface
    UdpConn : *net.UDPConn // UDPConn connecting with B
    LocalIPAddress : 192.168.0.1 // A's interface addr
    RemoteIPAddress : 192.168.0.2 // B's interface addr
    Activated : true // up if true
    }
*/
func parseLnx(filepath string) (extInterfaces []*link.ExternalInterface, hostAddr string, portNumber string, myVIPs map[string]bool) {
	extInterfaces = make([]*link.ExternalInterface, 0)
	myVIPs = make(map[string]bool)
	f, err := os.Open(filepath)
	if err != nil {
		log.Fatalln(err)
	}
	defer f.Close()
	var count = 0
	var id = 0
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		// first line is the information about the self (router) e.g. localhost 5000
		if count == 0 {
			strs := strings.Fields(scanner.Text())
			hostAddr = strs[0]
			portNumber = strs[1]
			count += 1
		} else {
			// line(s) after contain information about the interfaces
			strs := strings.Fields(scanner.Text())
			extAddress := strs[0]
			extPort := strs[1]
			locIntIpAddr := net.ParseIP(strs[2])
			//our host can have interface number of VIPs
			myVIPs[locIntIpAddr.String()] = true
			extIntIpAddr := net.ParseIP(strs[3])
			// dial udpaddr for B and get the conn
			remoteAddress := resolveNeighbor(extAddress, extPort)
			extInt := &link.ExternalInterface{
				Id:              id,
				RemoteAddress:   remoteAddress,
				LocalIPAddress:  locIntIpAddr,
				RemoteIPAddress: extIntIpAddr,
				Activated:       true,
			}
			id += 1
			extInterfaces = append(extInterfaces, extInt)
		}
	}
	if err := scanner.Err(); err != nil {
		log.Fatal(err)
	}

	return extInterfaces, hostAddr, portNumber, myVIPs
}

/*
* Function that adds the src router's VIP(s) to its own Hop Table
*
* @param nodeInfo: Struct containing vital information about the router
 */
func addToHopsTable(nodeInfo *info.NodeInfo) {
	rt := nodeInfo.Table
	for myVIP, _ := range nodeInfo.LocalIPs {
		intIp, err := packet.Ip2int(net.ParseIP(myVIP))
		if err != nil {
			log.Fatalln("Converting IPv4 to int32:", err)
		}
		selfHopData := &packet.HopData{
			Cost:    0,
			Address: intIp,
			Mask:    packet.MAX_UINT32,
		}
		// not setting the UpdatedAt field as this is a constant entry
		selfHop := &routing.Hop{
			Data:   selfHopData,
			Sender: intIp,
		}
		rt.HopMtx.Lock()
		rt.Hops[myVIP] = selfHop
		rt.HopMtx.Unlock()
	}

}

func updateExtInterface(nodeInfo *info.NodeInfo, extInterfaces []*link.ExternalInterface) {
	for _, extInt := range extInterfaces {
		extInt.HostConn = nodeInfo.Conn
	}
}

/*
* Helper function that gets called when the "q" command is typed in the terminal
* It will loop through all the connected sockets and remove them accordingly.
* Then it will loop through all the listening sockets and remove hem accordingly
*/
func closeAllSock(nodeInfo *info.NodeInfo){
	//all the VTCPConns
	for _, curSock := range nodeInfo.SocketTable.SockTable {
		if string(curSock.State) == "SYN_SENT" || string(curSock.State) == "SYN_RECEIVED" {
			nodeInfo.SocketTable.SockTableMtx.Lock()
			delete(nodeInfo.SocketTable.SockTable, curSock.SID)
			nodeInfo.SocketTable.SockTableMtx.Unlock()
			return
		}
		curSock.IsTerm = true
		curSock.TermStart = time.Now()
		temp.VCloseConn(nodeInfo, curSock, true)
	}
	//all the VTCPListener
	for _, lisSock := range nodeInfo.SocketTable.ListeningSocks {
		close(lisSock.ClientInfoChan)
		nodeInfo.SocketTable.LisTableMtx.Lock()
		delete(nodeInfo.SocketTable.ListeningSocks, lisSock.SID)
		nodeInfo.SocketTable.LisTableMtx.Unlock()
		nodeInfo.SocketTable.UnbindPort(lisSock.SID)
	}

	nodeInfo.SocketWaitGroup.Wait()
}

func main() {
	if len(os.Args) != 2 {
		log.Fatalf("Usage:  %s <linksfile>\n", os.Args[0])
	}

	//populate the interfaces for this router and store it in extInterfaces
	extInterfaces, hostAddr, portNumber, myVIPs := parseLnx(os.Args[1])
	//initialize the Forwarding Table with information about adjacent routers
	rt := routing.CreateRoutingTable(extInterfaces)
	// initialize node info

	for _, intf := range extInterfaces {
		fmt.Printf("%d: %s\n", intf.Id, intf.LocalIPAddress)
	}

	bindAddrStr, err := net.ResolveUDPAddr("udp4", fmt.Sprintf("%s:%s", hostAddr, portNumber))
	if err != nil {
		log.Fatalln("Error translating address:  ", err)
	}

	conn, err := net.ListenUDP("udp4", bindAddrStr)
	if err != nil {
		log.Fatalln("Error listening to port:  ", err)
	}

	nodeInfo := &info.NodeInfo{
		Table: rt,
		SocketTable: &socket.SocketTable{
			NextSID:        0,
			SockTable:      make(map[uint16]*socket.VTCPConn),
			ListeningSocks: make(map[uint16]*socket.VTCPListener),
			PORT_TO_SID:    make(map[uint16]uint16),
			UsedPorts:      make(map[uint16]bool),
		},
		Conn:     conn,
		LocalIPs: myVIPs,
		InternalInterface: &info.InternalInterface{
			Handlers: make(map[int]info.HandlerFn),
		},
		PrintChan:      make(chan string, 1000),
		TracerouteChan: make(chan string), // this will only be used for traceroute
		IpPacketChan:   make(chan *packet.IpPacket),
		SendPacketChan: make(chan *packet.SendPacketRequest), // this is used for TCP sockets to send out IP packets

	}

	updateExtInterface(nodeInfo, extInterfaces)
	// register in hops table
	addToHopsTable(nodeInfo)

	// register handlers
	nodeInfo.InternalInterface.RegisterHandler(packet.TEST_PROTOCOL, temp.TestPacketHandler)
	nodeInfo.InternalInterface.RegisterHandler(packet.RIP_PROTOCOL, temp.RipPacketHandler)
	nodeInfo.InternalInterface.RegisterHandler(packet.ICMP_PROTOCOL, temp.ICMPPacketHandler)
	nodeInfo.InternalInterface.RegisterHandler(packet.TCP_PROTOCOL, temp.TCPPacketHandler)

	/*
	* GO routines
	* HandleUdpListener -> a thread for listening packets
	* RipProtocolSender -> a thread that handles RIP Protocol (triggers, periodic updates, etc.)
	* StartCommandLine  ->  a thread for handling user command line input
	* ISNGenerator -> a thread that simulates a "clock"
	* IpPacketSender -> a thread that reads from a channel and helps sockets send out ip packets
	 */
	go temp.HandleUdpListener(nodeInfo.Conn, nodeInfo.IpPacketChan)

	go temp.RipProtocolSender(nodeInfo)

	go temp.RefreshTable(nodeInfo)

	go temp.RefreshSocketTable(nodeInfo)

	go temp.StartCommandLine(nodeInfo)

	go temp.ISNGenerator()

	go temp.IpPacketSender(nodeInfo)

	// greet the neighbors by sending routing request
	requestRoutes(extInterfaces)

	for {
		select {
		case output, more := <-nodeInfo.PrintChan:
			if more {
				fmt.Print(output)
			} else {
				fmt.Println("Closing all sockets...")
				closeAllSock(nodeInfo)
				fmt.Println("Closing node...")
				os.Exit(0)
			}
		case ipPacket := <-nodeInfo.IpPacketChan:
			handleIpPackets(nodeInfo, ipPacket)
		}
	}
}
