package socket

import (
	"math/rand"
	"sync"
	"time"
)

/*
* (Normal) Socket Identifier which contains the 4-tuple identifier
 */
type SocketIdentifier struct {
	LocalIPAddress  uint32
	LocalPort       uint16
	RemoteIPAddress uint32
	RemotePort      uint16
}

/*
* Socket Table struct that contains all socket-related information for a node
*
* NextSID: next available socket id number
* SockTable: maps socket id to the connection
* ListeningSocks: maps socket id to listen sockets
* PORT_TO_SID: maps port to listening sockets
*
* NextSIDMtx: Mutex to protect assigning new socket IDs
*
 */
type SocketTable struct {
	NextSID        uint16
	SockTable      map[uint16]*VTCPConn
	ListeningSocks map[uint16]*VTCPListener
	PORT_TO_SID    map[uint16]uint16
	UsedPorts      map[uint16]bool

	NextSIDMtx sync.Mutex
	SockTableMtx sync.Mutex
	LisTableMtx sync.Mutex
}

/*
* This function gets an available port. Port number returned will be reserved.
 */
func (st *SocketTable) GetNewPort(port uint16) (localPort uint16) {
	portBound := true
	for portBound {
		rand.Seed(time.Now().UnixNano())
		localPort = uint16(rand.Intn(MAX_PORT-MIN_PORT+1) + MIN_PORT)
		portBound = st.IsPortBound(localPort)
	}

	// set port as used
	st.BindPort(localPort)

	return localPort
}

/*
* This function reserves a port number
 */
func (st *SocketTable) BindPort(port uint16) {
	st.UsedPorts[port] = true
}

/*
* This function frees up a port number
 */
func (st *SocketTable) UnbindPort(port uint16) {
	delete(st.UsedPorts, port)
}

/*
* This function checks for port availability
 */
func (st *SocketTable) IsPortBound(port uint16) bool {
	_, ok := st.UsedPorts[port]
	return ok
}

/*
* This function returns a new SID and increments existing available SID by one
 */
func (st *SocketTable) GetNewSID() uint16 {
	st.NextSIDMtx.Lock()
	defer st.NextSIDMtx.Unlock()

	newSID := st.NextSID
	st.NextSID += 1
	return newSID
}
