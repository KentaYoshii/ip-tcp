package temp

import (
	"bufio"
	"fmt"
	"ip/pkg/info"
	"ip/pkg/packet"
	"ip/pkg/routing"
	"log"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
	"golang.org/x/net/ipv4"
)

func ConstructHelpMessage() string {
	//IP driver commands
	out := "----------------------------------------Supported Commands-----------------------------------------------------------------------\n"
	out += "interfaces, li : Prints information about each interface, one per line\n"
	out += "interfaces <file>, li <file> : Print information about each interface, one per line, to the destination file\n"
	out += "routes, lr : Print information about the route to each known destination\n"
	out += "routes <file>, lr <file> : Print information about the route to each known destination, one per line, to the destination file\n"
	out += "down <integer> : Bring an interface with ID <integer> “down”\n"
	out += "up <integer> : Bring an interface with ID <integer> “up”\n"
	out += "traceroute <vip> : start a traceroute to vip\n"
	out += "send <vip> <proto> <string> : Send an IP packet with protocol <proto> to the virtual IP address <vip>. The payload is simply the characters of <string>\n"
	out += "q : quit the node\n"
	//TCP driver commands
	out += "h : print list of supported commands\n"
	out += "ls : List all sockets, along with the state the TCP connection associated with them is in, and their window sizes\n"
	out += "a <port> : Open a socket, bind it to the given port on any interface, and start accepting connections on that port\n"
	out += "c <ip> <port> : Attempt to connect to the given IP address on the given port\n"
	out += "s <socket ID> <data> : Send a string on a socket\n"
	out += "r <socket ID> <numbytes> <y|n> : Try to read data from a given socket. If the last argument is y, then you should block until numbytes is received, or the connection closes. If n, then don't block\n"
	out += "sd <socket ID> <read|write|both> : VShutdown on the given socket. If read or r is given, close only the reading side. If write or w is given, close only the writing side. If both is given, close both sides\n"
	out += "cl <socket ID> : VClose() on the given socket\n"
	out += "sf <filename> <ip> <port> : Connect to the given IP and port, send the entirety of the specified file, and close the connection\n"
	out += "rf <filename> <port> : Listen for a connection on the given port. Once established, write everything you can read from the socket to the given file. Once the other side closes the connection, close the connection as well\n"
	//TCP capstone
	out += "lc : print the avaiable congestion control algorithm\n"
	out += "sc <socket ID> <string> : Sets the congestion control algorithm for the given socket. To disable congestion control, use the string: none\n"
	out += "----------------------------------------------------------------------------------------------------------------------------------\n"
	return out

}

/*
* Function that starts the CLI by calling Scan()
*
* @param nodeInfo: node info struct containing relevant channels and information
 */
func StartCommandLine(nodeInfo *info.NodeInfo) {
	scanner := bufio.NewScanner(os.Stdin)
	nodeInfo.PrintChan <- "> "
	for {
		scanner.Scan()
		line := scanner.Text()
		if strings.TrimSpace(line) == "q" {
			close(nodeInfo.PrintChan)
			return
		} else {
			HandleCommandLine(nodeInfo, line)
			nodeInfo.PrintChan <- "> "
		}
	}

}

/*
* Function that handles the "interfaces" or "li" command.
* Prints out the list of External Interfaces the router has in the following format

* id state     local       remote       port
* 0   up    192.168.0.1  192.168.0.1    5001
* ....
*
* @param nodeInfo : nodeInfo struct
 */
func PrintInterfaces(nodeInfo *info.NodeInfo) {
	rt := nodeInfo.Table
	output := "id   state      local          remote        port\n"
	for _, extInterface := range rt.Interfaces {
		var activeString = ""
		if extInterface.Activated {
			activeString = "up"
		} else {
			activeString = "down"
		}

		interfaceOutput := fmt.Sprintf("%d     %s     %s     %s     %d\n",
			extInterface.Id,
			activeString, extInterface.LocalIPAddress.String(),
			extInterface.RemoteIPAddress.String(),
			extInterface.RemoteAddress.Port)

		output += interfaceOutput
	}

	nodeInfo.PrintChan <- output
}

/*
* Function that takes in a filepath and writes to it the
* interfaces information for this router
*
* @param destPath : filepath we will write to. Truncate if it exists
* @param rt : Routing Table for src router
 */
func WriteInterfaces(destPath string, rt *routing.RoutingTable) {
	stringToWrite := "id   state      local          remote        port\n"
	for _, extInterface := range rt.Interfaces {
		// external interface
		var activeString = ""
		if extInterface.Activated {
			activeString = "up"
		} else {
			activeString = "down"
		}
		stringToWrite += fmt.Sprintf("%d     %s     %s     %s     %d\n",
			extInterface.Id, activeString, extInterface.LocalIPAddress.String(), extInterface.RemoteIPAddress.String(), extInterface.RemoteAddress.Port)
	}
	err := os.WriteFile(destPath, []byte(stringToWrite), 0666)
	if err != nil {
		log.Fatal(err)
	}
}

/*
* Function that handles the "routes" or "lr" command.
* Prints out the list of Entries in the src host Routing Table (ASC cost)
*
* dest            next             cost
* 192.168.0.2     192.168.0.2      1
* 192.168.0.4     192.168.0.4      1
*
* @param nodeInfo : nodeInfo struct
 */
func PrintRouteInfo(nodeInfo *info.NodeInfo) {
	rt := nodeInfo.Table

	entries := make([]*routing.Hop, 0)
	for _, entry := range rt.Hops {
		entries = append(entries, entry)
	}

	sort.Slice(entries, func(i, j int) bool {
		return entries[i].Data.Cost < entries[j].Data.Cost
	})

	outString := "dest            next             cost\n"
	for _, sortedEntry := range entries {
		outString += fmt.Sprintf("%s     %s      %d\n", packet.Int2ip(sortedEntry.Data.Address), packet.Int2ip(sortedEntry.Sender), sortedEntry.Data.Cost)
	}

	nodeInfo.PrintChan <- outString
}

/*
* Function that takes in a filepath and writes to it the
* routes information for this router
*
* @param destPath : filepath we will write to. Truncate if it exists
* @param rt : Routing Table for src router
 */
func WriteRouteInfo(destPath string, rt *routing.RoutingTable) {
	entries := make([]*routing.Hop, 0)
	for _, entry := range rt.Hops {
		entries = append(entries, entry)
	}

	sort.Slice(entries, func(i, j int) bool {
		return entries[i].Data.Cost < entries[j].Data.Cost
	})

	outString := "dest            next             cost\n"
	for _, sortedEntry := range entries {
		outString += fmt.Sprintf("%s     %s      %d\n", packet.Int2ip(sortedEntry.Data.Address), packet.Int2ip(sortedEntry.Sender), sortedEntry.Data.Cost)
	}

	err := os.WriteFile(destPath, []byte(outString), 0666)
	if err != nil {
		log.Fatal(err)
	}
}

/*
* Function that gets called with the "send" command
* This will create the IP Header, marshal the bytes, and send to the
* next Hop Address obtained through the forwarding table
*
* @param nodeInfo : node info struct
* @param proto : protocol (200/0/1)
* @param ttl: TTL value, typically should be
* @param payload : payload to be included in the packet
* @param overwriteSrcAddress: src address to be overwritten in IP packet header (edge case for multiple interface TCP)
 */
func SendPacket(nodeInfo *info.NodeInfo, dest string, proto int, ttl int, payload []byte, overwriteSrcAddress string) {
	// construct packet first
	if proto == 200 {
		hops := nodeInfo.Table.GetAllExtHops()
		ripPacket := &packet.RipPacket{
			Command:     2, // should always be 2
			Num_entries: uint16(len(hops)),
			Entries:     hops,
		}
		payload = ripPacket.Marshal()
	}

	if nodeInfo.IsMyVIP(dest) {
		ipHeader := packet.ConstructIPHeader(dest, dest, len(payload), proto, ttl)
		ipPacket := &packet.IpPacket{
			Header:  ipHeader,
			Payload: payload,
		}
		nodeInfo.PrintChan <- ipPacket.String()
		return
	} else {
		// if dest != one of the src's IPs then we forward
		externalInterface, err := nodeInfo.Table.Lookup(dest)
		if err != nil {
			nodeInfo.PrintChan <- err.Error() + "\n"
			return
		}
		if !externalInterface.Activated {
			nodeInfo.PrintChan <- "Interface is down\n"
			return
		}

		var ipHeader *ipv4.Header

		if proto == packet.TCP_PROTOCOL && overwriteSrcAddress != "" {
			//if the proto is TCP, then we need to fake the SRC so that we can handle node with multiple interfaces
			//the method Nick recommended
			ipHeader = packet.ConstructIPHeader(overwriteSrcAddress, dest, len(payload), proto, ttl)
		} else {
			//get the src router's corresponding LocalIP
			localIP := externalInterface.LocalIPAddress
			ipHeader = packet.ConstructIPHeader(localIP.String(), dest, len(payload), proto, ttl)
		}

		hdrBytes, err := ipHeader.Marshal()
		if err != nil {
			log.Fatalln("Error on marshal: ", err)
		}
		ipHeader.Checksum = int(packet.ComputeChecksum(hdrBytes))

		ipPacket := &packet.IpPacket{
			Header:  ipHeader,
			Payload: payload,
		}
		bytesToSend := ipPacket.Marshal()
		_, err = externalInterface.HostConn.WriteToUDP(bytesToSend, externalInterface.RemoteAddress)
		if err != nil {
			log.Panicln("Error writing to socket: ", err)
		}
	}
}

/*
* Function that handles user command line input
*
* @param nodeInfo: node info struct that contains necessary node information and channels
* @param command : user command input
 */
func HandleCommandLine(nodeInfo *info.NodeInfo, command string) {
	commands := strings.Fields(command)
	if len(commands) > 0 {
		switch commands[0] {
		// print out/write all the interface information
		case "interfaces", "li":
			if len(commands) == 2 {
				WriteInterfaces(commands[1], nodeInfo.Table)
			} else {
				PrintInterfaces(nodeInfo)
			}
			return
			// print out/write the routes to other routers
		case "routes", "lr":
			if len(commands) == 2 {
				WriteRouteInfo(commands[1], nodeInfo.Table)
			} else {
				PrintRouteInfo(nodeInfo)
			}
			return

		case "down":
			if len(commands) != 2 {
				nodeInfo.PrintChan <- "format should be: down <id>\n"
				return
			}

			// Making sure it's int
			id, err := strconv.Atoi(commands[1])
			if err != nil {
				nodeInfo.PrintChan <- "format should be: down <id>\n"
				return
			}

			err = nodeInfo.Table.DeactivateInterface(id)
			if err != nil {
				nodeInfo.PrintChan <- err.Error() + "\n"
			}
			return

		case "up":
			if len(commands) != 2 {
				nodeInfo.PrintChan <- "format should be: up <id>\n"
				return
			}

			id, err := strconv.Atoi(commands[1])
			if err != nil {
				nodeInfo.PrintChan <- "format should be: up <id>\n"
				return
			}

			err = nodeInfo.Table.ActivateInterface(id)
			if err != nil {
				nodeInfo.PrintChan <- err.Error() + "\n"
			}
			return

		case "send":
			// send out a TEST/RIP packet to <vip>
			// min 3 args needed
			if len(commands) < 3 {
				nodeInfo.PrintChan <- "wrong format: send <vip> <proto> <payload>\n"
				return
			}

			destination := commands[1]
			// if ip is not in dotted quad notation
			if net.ParseIP(destination) == nil {
				nodeInfo.PrintChan <- "<vip> should be a ip addr with dotted quad notation\n"
				return
			}
			proto := commands[2]
			protocol, ok := strconv.Atoi(proto)
			// if protocol inputted is not an int
			if ok != nil {
				nodeInfo.PrintChan <- "<proto> should be int value of either 200 or 0\n"
				return
			}
			// if protocol is not supported
			if protocol != 200 && protocol != 0 {
				nodeInfo.PrintChan <- "<proto> should be int value of either 200 or 0\n"
				return
			}

			// if it is TEST protocol we need <vip> <proto> <payload>
			if protocol == 0 && len(commands) < 4 {
				nodeInfo.PrintChan <- "You protocol 0 requires <vip> <proto> <payload>\n"
				return
			}

			payload := ""
			switch protocol {
			// TEST protocol
			case 0:
				if len(commands) > 4 {
					payload = strings.Join(commands[3:], " ")
				} else {
					payload = commands[3]
				}
				SendPacket(nodeInfo, destination, protocol, packet.DEFAULT_TTL, []byte(payload), "")
				return
			case 200:
				// RIP do not care about payload
				SendPacket(nodeInfo, destination, protocol, packet.DEFAULT_TTL, []byte(payload), "")
				return
			}

		case "h":
			// print supported cmds
			nodeInfo.PrintChan <- ConstructHelpMessage()
			return

		case "traceroute":
			if len(commands) != 2 {
				nodeInfo.PrintChan <- "wrong format: traceroute <vip>\n"
				return
			}

			StartTraceroute(nodeInfo, commands[1])
			return
		case "ls":
			outString := nodeInfo.PrintSocketTable()
			nodeInfo.PrintChan <- outString
			return
		case "a":
			if len(commands) != 2 {
				nodeInfo.PrintChan <- "format should be: a <port>\n"
				return
			}

			port, err := strconv.Atoi(commands[1])
			if err != nil {
				nodeInfo.PrintChan <- "<port> has to be an integer\n"
				return
			}
			port16 := uint16(port)

			// bind socket to port
			listener, err := VListen(port16, nodeInfo)
			if err != nil {
				nodeInfo.PrintChan <- fmt.Sprintf("v_bind() error: %s\n", err.Error())
				return
			}

			nodeInfo.PrintChan <- fmt.Sprintf("Accepting connections on port %d\n", port)
			// Start accepting all connections on this listener
			nodeInfo.SocketWaitGroup.Add(1)
			go AcceptAllConnections(listener, nodeInfo)

		case "c":
			if len(commands) != 3 {
				nodeInfo.PrintChan <- "format should be: c <ip> <port>\n"
				return
			}
			destination := commands[1]
			// if ip is not in dotted quad notation
			if net.ParseIP(destination) == nil {
				nodeInfo.PrintChan <- "<vip> should be a ip addr with dotted quad notation\n"
				return
			}
			port := commands[2]
			portInt, ok := strconv.Atoi(port)
			// if protocol inputted is not an int
			if ok != nil {
				nodeInfo.PrintChan <- "<port> has to be an integer\n"
				return
			}
			//create a new conn
			VConnect(destination, uint16(portInt), nodeInfo.PrintChan, nodeInfo)
			return
		case "s":
			// Send a string on a socket. This should block until VWrite() returns.
			if len(commands) < 3 {
				nodeInfo.PrintChan <- "format should be: s <socket ID> <data>\n"
				return
			}

			sid, err := strconv.Atoi(commands[1])
			if err != nil {
				nodeInfo.PrintChan <- "<socket ID> has to be an integer\n"
				return
			}
			var data string
			if len(commands) >= 4 {
				data = strings.Join(commands[2:], " ")
			} else {
				data = commands[2]
			}

			// find socket
			if conn, ok := nodeInfo.SocketTable.SockTable[uint16(sid)]; ok {
				//we sd the writing part of the socket
				if conn.WriteClose {
					nodeInfo.PrintChan <- "v_write() error: Cannot send after transport endpoint shutdown\n"
					return
				}
				bytesWritten, err := VWrite(conn, []byte(data))
				if err != nil {
					nodeInfo.PrintChan <- fmt.Sprintf("writing error: %s\n", err.Error())
					return
				} else {
					nodeInfo.PrintChan <- fmt.Sprintf("wrote %d bytes on socket %d\n", bytesWritten, sid)
				}
			} else {
				nodeInfo.PrintChan <- "socket not found\n"
				return
			}

			return
		case "r":
			if len(commands) < 3 {
				nodeInfo.PrintChan <- "format should be: r <socket ID> <numbytes> <y|n>\n"
				return
			}
			sid, err := strconv.Atoi(commands[1])
			if err != nil {
				nodeInfo.PrintChan <- "<socket ID> has to be an integer\n"
				return
			}

			numBytes, err := strconv.Atoi(commands[2])
			if err != nil {
				nodeInfo.PrintChan <- "<numbytes> has to be an integer\n"
				return
			}

			option := ""
			if len(commands) == 3 {
				option = "n"
			} else {
				option = commands[3]
				if option != "n" && option != "y" {
					nodeInfo.PrintChan <- "invalid option\n"
					return
				}
			}

			// find socket
			conn, ok := nodeInfo.SocketTable.SockTable[uint16(sid)]
			if !ok {
				nodeInfo.PrintChan <- "socket not found\n"
				return
			}

			if conn.ReadClose {
				nodeInfo.PrintChan <- "v_read() error: Operation not permitted\n"
				return
			}

			if option == "n" {
				readBuffer := make([]byte, numBytes)
				bytesRead, err := VRead(conn, readBuffer)
				if err != nil {
					nodeInfo.PrintChan <- fmt.Sprintf("reading error: %s\n", err.Error())
					return
				}
				nodeInfo.PrintChan <- fmt.Sprintf("Read %d bytes: %s\n", bytesRead, string(readBuffer[:bytesRead]))
			} else {
				// BLOCKS UNTIL NUMBYTES RECEIVED
				totalBytesRead := 0
				resultBuffer := make([]byte, 0)
				for totalBytesRead < numBytes {
					readBuffer := make([]byte, numBytes-totalBytesRead)
					bytesRead, err := VRead(conn, readBuffer)
					if err != nil {
						if totalBytesRead > 0 {
							// we have read some bytes into result buffer
							nodeInfo.PrintChan <- fmt.Sprintf("Read %d bytes: %s\n", totalBytesRead, resultBuffer)
						}
						nodeInfo.PrintChan <- fmt.Sprintf("reading error: %s\n", err.Error())
						return
					}
					totalBytesRead += bytesRead
					resultBuffer = append(resultBuffer, readBuffer[:bytesRead]...)
				}
				nodeInfo.PrintChan <- fmt.Sprintf("Read %d bytes: %s\n", totalBytesRead, string(resultBuffer))
			}
		case "sd":
			if len(commands) < 2 {
				nodeInfo.PrintChan <- "format should be: sd <socket ID> <read|write|both>\n"
				return
			}
			sid, err := strconv.Atoi(commands[1])
			if err != nil {
				nodeInfo.PrintChan <- "<socket ID> has to be an integer\n"
				return
			}

			// find socket
			conn, ok := nodeInfo.SocketTable.SockTable[uint16(sid)]
			if !ok {
				nodeInfo.PrintChan <- "socket not found\n"
				return
			}

			option := 0
			if len(commands) == 2 {
				option = 1
			} else {
				if commands[2] == "read" {
					option = 2
				} else if commands[2] == "both" {
					option = 3
				} else if commands[2] == "write" {
					option = 1
				} else {
					nodeInfo.PrintChan <- "Supported options are <read | write | both>\n"
					return 
				}

			}
			//calling sd write after it was already called
			if conn.WriteClose && option == 1 {
				nodeInfo.PrintChan <- "error: connection closing[writing]\n"
				return
			}

			//ditto for reading
			if conn.ReadClose && option == 2 {
				nodeInfo.PrintChan <- "error: connection closing[reading]\n"
				return
			}

			//just wait boy
			if string(conn.State) == "TIME_WAIT" {
				nodeInfo.PrintChan <- "error: connection closing\n"
				return
			}
			VShutdown(nodeInfo, conn, option)
			return
		case "cl":
			if len(commands) < 2 {
				nodeInfo.PrintChan <- "format should be: cl <socket ID>\n"
				return
			}
			sid, err := strconv.Atoi(commands[1])
			if err != nil {
				nodeInfo.PrintChan <- "<socket ID> has to be an integer\n"
				return
			}
			lisSock, isLis := nodeInfo.SocketTable.ListeningSocks[uint16(sid)]
			if isLis {
				close(lisSock.ClientInfoChan)
				nodeInfo.SocketTable.LisTableMtx.Lock()
				delete(nodeInfo.SocketTable.ListeningSocks, lisSock.SID)
				nodeInfo.SocketTable.LisTableMtx.Unlock()
				nodeInfo.SocketTable.UnbindPort(lisSock.SID)
				delete(nodeInfo.SocketTable.PORT_TO_SID, lisSock.LocalPort)

				return
			}
			//check if we have the input socket id in our map
			conn, ok := nodeInfo.SocketTable.SockTable[uint16(sid)]
			if !ok {
				nodeInfo.PrintChan <- "socket not found\n"
				return
			}

			//already been called
			if conn.WriteClose && conn.ReadClose {
				nodeInfo.PrintChan <- "error: connection closing[reading|writing]\n"
				return
			}

			if string(conn.State) == "SYN_SENT" {
				nodeInfo.SocketTable.SockTableMtx.Lock()
				delete(nodeInfo.SocketTable.SockTable, conn.SID)
				nodeInfo.SocketTable.SockTableMtx.Unlock()
				return
			}

			if string(conn.State) == "SYN_RECEIVED" {
				nodeInfo.SocketTable.SockTableMtx.Lock()
				delete(nodeInfo.SocketTable.SockTable, conn.SID)
				nodeInfo.SocketTable.SockTableMtx.Unlock()
				return
			}

			VCloseConn(nodeInfo, conn, false)
			return
		case "sf":
			if len(commands) < 4 {
				nodeInfo.PrintChan <- "format should be: sf <filename> <ip> <port> <cc-algo>\n"
				return
			}
			destination := commands[2]
			// if ip is not in dotted quad notation
			if net.ParseIP(destination) == nil {
				nodeInfo.PrintChan <- "<ip> should be a ip addr with dotted quad notation\n"
				return
			}
			port := commands[3]
			port16, ok := strconv.Atoi(port)
			// if protocol inputted is not an int
			if ok != nil {
				nodeInfo.PrintChan <- "<port> has to be an integer\n"
				return
			}
			var ccAlgo string
			if len(commands) > 4 && commands[4] == "tahoe" {
				ccAlgo = commands[4]
			} else {
				ccAlgo = ""
			}
			go SendFile(commands[1], destination, uint16(port16), nodeInfo, ccAlgo)
			return
		case "rf":
			if len(commands) != 3 {
				nodeInfo.PrintChan <- "format should be: rf <filename> <port>\n"
				return
			}
			port := commands[2]
			portI, ok := strconv.Atoi(port)
			// if protocol inputted is not an int
			if ok != nil {
				nodeInfo.PrintChan <- "<port> has to be an integer\n"
				return
			}
			go ReadFile(commands[1], uint16(portI), nodeInfo)
			return

		case "lc":
			// print congestion control algo names
			nodeInfo.PrintChan <- "tahoe\n"
			return
		case "sc":
			// Sets the congestion control algorithm for the given socket. To disable congestion control, use the string: none
			if len(commands) < 3 {
				nodeInfo.PrintChan <- "format should be: sc <socket ID> <string>\n"
				return
			}
			sid, err := strconv.Atoi(commands[1])
			if err != nil {
				nodeInfo.PrintChan <- "<socket ID> has to be an integer\n"
				return
			}

			algo := commands[2]
			if algo != "tahoe" && algo != "none" {
				nodeInfo.PrintChan <- "Invalid congestion control algorithm\n"
				return
			}

			// find socket
			conn, ok := nodeInfo.SocketTable.SockTable[uint16(sid)]
			if !ok {
				nodeInfo.PrintChan <- "socket not found\n"
				return
			}

			if algo == "none" {
				conn.CCAlgo = ""
			} else {
				conn.CCAlgo = algo
			}
			nodeInfo.PrintChan <- fmt.Sprintf("socket %d set to use %s congestion control algorithm\n", sid, algo)

		default:
			nodeInfo.PrintChan <- "Command not supported: type 'h' to get the list of supported commands\n"
		}
	}
}
