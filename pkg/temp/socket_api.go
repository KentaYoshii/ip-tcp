package temp

import (
	"errors"
	"fmt"
	"io"
	"ip/pkg/info"
	"ip/pkg/packet"
	"ip/pkg/socket"
	"log"
	"math/rand"
	"net"
	"os"
	"time"

	"github.com/google/netstack/tcpip/header"
)

var usedPorts = make(map[uint16]bool)

/*
* Helper function that checks if the input VTCPConn matches the input 4 tuple
 */
func IsMatchSocket(curSock *socket.VTCPConn, f_tup *socket.SocketIdentifier) bool {
	if curSock.LocalIPAddress == f_tup.LocalIPAddress &&
		curSock.LocalPort == f_tup.LocalPort &&
		curSock.RemoteIPAddress == f_tup.RemoteIPAddress &&
		curSock.RemotePort == f_tup.RemotePort {
		return true
	} else {
		return false
	}

}

/* *** FUNCTIONS FOR LISTENING SOCKETS (VTCPListener) *** */

/*
 * Create a new listening socket bound to the specified port on any
 * of this node's interfaces.
 * After binding, this socket moves into the LISTEN state (passive
 * open in the RFC)
 *
 * Returns a TCPListener on success.  On failure, returns an
 * appropriate error in the "error" value
 */
func VListen(port uint16, nodeInfo *info.NodeInfo) (*socket.VTCPListener, error) {
	// check for port availability
	socketTable := nodeInfo.SocketTable
	portBound := socketTable.IsPortBound(port)
	if portBound {
		return nil, errors.New("port already in use")
	}

	// get new SID
	curID := socketTable.GetNewSID()

	// create listener
	newListenSock := &socket.VTCPListener{
		SID:             curID,
		LocalPort:       port,
		ClientInfoQueue: make([]socket.SocketIdentifier, 0),
		ClientInfoChan:  make(chan socket.TCPClientInfo, socket.MAX_CLIENT_INFO_QUEUE),
		FinChan:         make(chan bool),
	}

	// reserve port
	socketTable.BindPort(port)

	// store socket
	socketTable.ListeningSocks[curID] = newListenSock
	socketTable.PORT_TO_SID[port] = curID
	return newListenSock, nil
}

/**
* This function allows a listener to automatically accept connections instead of manually calling VAccept
 */
func AcceptAllConnections(vtcpListener *socket.VTCPListener, nodeInfo *info.NodeInfo) {
	for {
		// VAccept will block if no new connections so this is efficient
		listener, err := VAccept(vtcpListener, nodeInfo)
		if err != nil {
			if err.Error() == "connection closed" {
				nodeInfo.SocketWaitGroup.Done()
				return
			}
			nodeInfo.PrintChan <- fmt.Sprintf("v_accept() error: %s\n> ", err.Error())
		} else {
			nodeInfo.PrintChan <- fmt.Sprintf("v_accept() on socket %d returned 1\n> ", listener.SID)
		}
	}
}

/*
 * Closes the listening socket.
 *
 * (Note) The removal of this socket from the table is done
 * inside CommandHandler since we don't have access to NodeInfo
 */
func VCloseListenConn(socket *socket.VTCPListener) error {
	//let gc handle the cleanup
	return nil
}

/*
* Get a port number available to this host
 */
func GetNewPort() uint16 {
	rand.Seed(time.Now().UnixNano())
	localPort := uint16(rand.Intn(socket.MAX_PORT-socket.MIN_PORT+1) + socket.MIN_PORT)
	_, ok := usedPorts[localPort]
	for ok {
		rand.Seed(time.Now().UnixNano())
		localPort = uint16(rand.Intn(socket.MAX_PORT-socket.MIN_PORT+1) + socket.MIN_PORT)
		_, ok = usedPorts[localPort]
	}
	usedPorts[localPort] = true
	return localPort
}

/* **** FUNCTIONS FOR NORMAL SOCKETS (VTCPConn) **** */

/*
 * Creates a new socket and connects to an
 * address:port (active OPEN in the RFC).
 * It then performs the threeway handshake
 */
func VConnect(remoteIPAddr string, port uint16, printChan chan string, nodeInfo *info.NodeInfo) uint16 {
	//get the ip addr that connects to this host
	outGoingInt, _ := nodeInfo.Table.Lookup(remoteIPAddr)
	localIPAddr := outGoingInt.LocalIPAddress.String()
	localPort := GetNewPort()
	localAddrInt, err := packet.Ip2int(net.ParseIP(localIPAddr))
	if err != nil {
		nodeInfo.PrintChan <- "error: parsing local IP address\n"
	}
	remoteAddrInt, err := packet.Ip2int(net.ParseIP(remoteIPAddr))
	if err != nil {
		nodeInfo.PrintChan <- "v_connect() error: No route to host\n"
	}
	//create a new VTCPConn with SYN-SENT state
	curSID := nodeInfo.SocketTable.GetNewSID()
	newConn := socket.CreateVTCPConn(
		curSID,
		localAddrInt,
		localPort,
		remoteAddrInt,
		port,
		socket.SYN_SENT,
		GetISN(),
		0,
		nodeInfo.SendPacketChan,
	)
	//add to the table
	nodeInfo.SocketTable.SockTable[curSID] = newConn
	newConn.IsTerm = false
	//perform a handshake
	ret := EstablishThreeWayHandshake(nodeInfo, newConn, remoteIPAddr)
	if ret == 1 {
		go newConn.StartSender() // handshake success, start sender goroutine
		nodeInfo.PrintChan <- "v_connect() returned 0\n"
	} else {
		nodeInfo.PrintChan <- "v_connect() returned -1: destination port does not exist\n"
		nodeInfo.SocketTable.SockTableMtx.Lock()
		delete(nodeInfo.SocketTable.SockTable, curSID)
		nodeInfo.SocketTable.SockTableMtx.Unlock()
	}
	return curSID
}

/*
* Waits for new TCP connections on this listening socket.  If no new
* clients have connected, this function MUST block until a new
* connection occurs.

* Returns a new VTCPConn for the new connection, non-nil error on failure.
 */
func VAccept(listener *socket.VTCPListener, nodeInfo *info.NodeInfo) (*socket.VTCPConn, error) {
	tcpClientInfo, more := <-listener.ClientInfoChan // this will block if the buffered channel is empty!
	if !more {
		return nil, errors.New("connection closed")
	}
	identifier := tcpClientInfo.Identifier

	// create a new VTCPConn
	curSID := nodeInfo.SocketTable.GetNewSID()
	sockConn := socket.CreateVTCPConn(
		curSID,
		identifier.LocalIPAddress,
		identifier.LocalPort,
		identifier.RemoteIPAddress,
		identifier.RemotePort,
		socket.SYN_RECEIVED,
		GetISN(),
		tcpClientInfo.Header.SeqNum+1,
		nodeInfo.SendPacketChan,
	)
	nodeInfo.SocketTable.SockTable[curSID] = sockConn

	// SEND BACK SYN + ACK
	tcpPacket := sockConn.CreateTCPPacket(sockConn.SeqN, []byte{})
	remoteIP := packet.Int2ip(sockConn.RemoteIPAddress)
	SendPacket(nodeInfo, remoteIP.String(), packet.TCP_PROTOCOL, packet.DEFAULT_TTL, tcpPacket.Marshal(), packet.Int2ip(sockConn.LocalIPAddress).String())

	sockConn.SeqN += 1
	sockConn.LastByteWritten = sockConn.SeqN - 1
	sockConn.OldestUnackedByte = sockConn.SeqN

	timeOutMap := map[int]int{0: 2, 1: 4, 2: 6, 3: 8}
	numReTransmit := 0

	// wait for ACK
	for {
		select {
		case tcpPacket := <- sockConn.PacketChan:
			if tcpPacket.Header.Flags == header.TCPFlagAck {
				
				// update values (although ack and lastbyteread shouldn't have changed)
				sockConn.AckN = tcpPacket.Header.SeqNum
				sockConn.LastByteRead = tcpPacket.Header.SeqNum - 1
				sockConn.ReceiverWindow = tcpPacket.Header.WindowSize
				sockConn.State = socket.ESTABLISHED
				//handshake completed
				go sockConn.StartSender()
				return sockConn, nil
			}
			//AcK is not coming, then SYN, AcK was dropped
		case <-time.After(time.Second * time.Duration(timeOutMap[numReTransmit])):
			// timeout
			fmt.Printf("trying attempt: %d\n", numReTransmit)
			if numReTransmit == 3 {
				return nil, errors.New("error")
			} else {
				numReTransmit += 1
				SendPacket(nodeInfo, remoteIP.String(), packet.TCP_PROTOCOL, packet.DEFAULT_TTL, tcpPacket.Marshal(), packet.Int2ip(sockConn.LocalIPAddress).String())
			}
		}
	}
}

/*
* Reads data from the TCP connection (RECEIVE in RFC)
* Data is read into slice passed as argument.
* VRead MUST block when there is no available data.  All reads should
* return at least one byte unless failure or EOF occurs.
* Returns the number of bytes read into the buffer.  Returned error
* is nil on success, io.EOF if other side of connection was done
sending, or other error describing other failure cases.
*/
func VRead(conn *socket.VTCPConn, buf []byte) (int, error) {
	// block when no available data
	for conn.UnreadBytes() == 0 {
		//If our socket is in CLOSE_WAIT state, that means the other end
		//are done sending. Return EOF
		if string(conn.State) == "CLOSE_WAIT" {
			return -1, errors.New("EOF")
		}
	}
	bytesToRead := len(buf)
	if int(conn.UnreadBytes()) < bytesToRead {
		bytesToRead = int(conn.UnreadBytes())
	}

	data := conn.ReceiveBuffer.Get(conn.LastByteRead+1, uint32(bytesToRead))
	copy(buf[:bytesToRead], data)
	conn.LastByteRead += uint32(bytesToRead)
	return bytesToRead, nil
}

/*
 * Write data to the TCP connection (SEND in RFC)
 *
 * Data written from byte slice passed as argument.  This function
 * MUST block until all bytes are in the send buffer.
 * Returns number of bytes written to the connection, error if socket
 * is closed or on other failures.
 */
func VWrite(conn *socket.VTCPConn, data []byte) (int, error) {
	spaceAvailable := conn.BufferSize - conn.SendBufferUsed()
	//hang until we have space for the length of data
	for spaceAvailable < uint32(len(data)) {
		spaceAvailable = conn.BufferSize - conn.SendBufferUsed()
	}
	bytesToWrite := len(data)
	conn.SendBuffer.Put(data, conn.LastByteWritten+1)
	conn.LastByteWritten += uint32(bytesToWrite)

	// trigger socket to send if possible
	conn.TriggerSendChan <- true

	return bytesToWrite, nil
}

/*
 * Shut down the connection
 *  - If type is 1, close the writing part of the socket (CLOSE in
 *    RFC).   T	his should send a FIN, and all subsequent writes to
 *    this socket return an error.  Any data not yet ACKed should
 *    still be retransmitted.
 *  - If type is 2, close the reading part of the socket (no RFC
 *    equivalent); all further reads on this socket should return 0,
 *    and the advertised window size should not increase any further.
 *  - If type is 3, do both.
 * Reuturns nil on success, error if socket already shutdown or for
 * other failures.
 *
 * NOTE:  When a socket is shut down, it is NOT immediately
 * invalidated--that is, it remains in the socket table until
 * it reaches the CLOSED state.
 */
func VShutdown(nodeInfo *info.NodeInfo, conn *socket.VTCPConn, sdType int) error {
	if sdType == 1 {
		conn.WriteClose = true
		if conn.State == socket.ESTABLISHED {
			nodeInfo.SocketWaitGroup.Add(1)
			//active closed
			go ActiveClose(nodeInfo, conn)
		} else if conn.State == socket.CLOSE_WAIT {
			nodeInfo.SocketWaitGroup.Add(1)
			//if other side already trying to
			conn.FinChan <- true
		}
		return nil
	} else if sdType == 2 {
		conn.ReadClose = true
		return nil
	} else {
		VShutdown(nodeInfo, conn, 2)
		VShutdown(nodeInfo, conn, 1)
		return nil
	}
}

/*
 * Invalidate this socket, making the underlying connection
 * inaccessible to ANY of these API functions.  If the writing part of
 * the socket has not been shutdown yet (ie, CLOSE in the RFC), then do
 * so.  Note that the connection shouldn't be terminated, and the socket
 * should not be removed from the socket table, until the connection
 * reaches the CLOSED state.  For example, after VClose() any data not yet ACKed should still be retransmitted.
 */
func VCloseConn(nodeInfo *info.NodeInfo, conn *socket.VTCPConn, isEnd bool) error {

	if !conn.ReadClose {
		VShutdown(nodeInfo, conn, 2) //close the read
	}
	if !conn.WriteClose {
		VShutdown(nodeInfo, conn, 1) //close the write
	}

	if !isEnd {
		nodeInfo.PrintChan <- "v_close() returned 0\n"
	}
	return nil
}

/*
* Function that gets called for the 'rf' command
 */
func ReadFile(fileName string, port uint16, nodeInfo *info.NodeInfo) {
	//listen at port
	newLis, _ := VListen(port, nodeInfo)
	//accept one client
	newConn, _ := VAccept(newLis, nodeInfo)
	//create/truncate a file
	resultBuffer := make([]byte, 0)
	readBuffer := make([]byte, 4096)

	b, e := VRead(newConn, readBuffer)
	total := b
	//read until EOF is received
	for e == nil {
		updateBuf := readBuffer[:b]
		resultBuffer = append(resultBuffer, updateBuf...)
		readBuffer = make([]byte, 4096)
		b, e = VRead(newConn, readBuffer)
		total += b
	}
	nodeInfo.PrintChan <- "EOF receied, rf finishing...\n> "
	//write the content to the file
	err := os.WriteFile(fileName, resultBuffer[:total], 0666)
	if err != nil {
		log.Fatal(err)
	}
	nodeInfo.PrintChan <- ""
	//close the conn
	VShutdown(nodeInfo, newConn, 1)
	nodeInfo.SocketTable.LisTableMtx.Lock()
	delete(nodeInfo.SocketTable.ListeningSocks, newLis.SID)
	nodeInfo.SocketTable.LisTableMtx.Unlock()
	nodeInfo.SocketTable.UnbindPort(newLis.SID)
	close(newLis.ClientInfoChan)
	delete(nodeInfo.SocketTable.PORT_TO_SID, port)

}

/*
* Funciton that gets called for the 'sf' command
 */
func SendFile(fileName string, destIP string, port uint16, nodeInfo *info.NodeInfo, ccAlgo string) {
	sid := VConnect(destIP, port, nodeInfo.PrintChan, nodeInfo)
	nodeInfo.PrintChan <- "> "
	sock := nodeInfo.SocketTable.SockTable[sid]
	sock.CCAlgo = ccAlgo
	//read file
	f, err := os.Open(fileName)
	if err != nil {
		log.Fatalf("unable to read file: %v", err)
	}
	defer f.Close()
	curSegment := make([]byte, 1024)
	for {
		n, err2 := f.Read(curSegment)
		if err2 == io.EOF {
			if n != 0 {
				VWrite(sock, curSegment[:n])
			}
			nodeInfo.PrintChan <- "EOF reached, finish reading\n> "
			VShutdown(nodeInfo, sock, 1)
			break
		}
		if err2 != nil {
			log.Fatal(err2)
			continue
		}
		//write the bytes we read
		VWrite(sock, curSegment[:n])
		curSegment = make([]byte, 1024)
	}
}
