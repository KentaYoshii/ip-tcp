package socket

type SocketState string

/*
* Passive Open: a process is willing to accept connections (our 'a' command)
* 	-> LISTEN state
* Active Open: a process is attempting to initiate a connection (our 'c' command)
*
 */

const (
	LISTEN       SocketState = "LISTEN"
	SYN_RECEIVED SocketState = "SYN_RECEIVED"
	SYN_SENT     SocketState = "SYN_SENT"
	ESTABLISHED  SocketState = "ESTABLISHED"
	FIN_WAIT_1   SocketState = "FIN_WAIT_1"
	FIN_WAIT_2   SocketState = "FIN_WAIT_2"
	CLOSING      SocketState = "CLOSING"
	TIME_WAIT    SocketState = "TIME_WAIT"
	CLOSE_WAIT   SocketState = "CLOSE_WAIT"
	LAST_ACK     SocketState = "LAST_ACK"
	CLOSED       SocketState = "CLOSED"
)
