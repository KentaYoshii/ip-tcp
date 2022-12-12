package temp

import (
	"fmt"
	"ip/pkg/info"
	"ip/pkg/packet"
	"ip/pkg/socket"
	"log"
	"time"

	"github.com/google/netstack/tcpip/header"
)

/*
* Function that gets called every time a socket starts a connection
* Retransmission is handled in the following manner
* 	After first SYN attempt
*	  if the conn has not be estab after 1s of sleep, resend
*     if the above is not acked, then resend after 2s
*     if the above is not acked, then resend after 4s
*     if the above is not acked, then resend after 8s
*     if the above is not acked, then forget about connecting
*
* @param nodeInfo : Information about this node
* @param newConn : New VTCPConn we want to handle
* @paaram dest : Destination host IP Address at which the listening port is located
 */
func EstablishThreeWayHandshake(nodeInfo *info.NodeInfo, newConn *socket.VTCPConn, dest string) int {
	timeOutMap := map[int]int{0: 2, 1: 4, 2: 6, 3: 8}
	numReTransmit := 0
	//construct the tcp packet payload with SYN
	newConn.State = socket.SYN_SENT
	outgoingTcpPacket := newConn.CreateTCPPacket(newConn.SeqN, []byte{})
	payload := outgoingTcpPacket.Marshal()

	//send it within UDP
	SendPacket(nodeInfo, dest, packet.TCP_PROTOCOL, packet.DEFAULT_TTL, payload, packet.Int2ip(newConn.LocalIPAddress).String())
    newConn.SeqN = newConn.SeqN + 1
	newConn.LastByteWritten = newConn.SeqN - 1
	newConn.OldestUnackedByte = newConn.SeqN
	
	// wait for ack
	for {
		select {
		case incomingTcpPacket := <-newConn.PacketChan:
			if incomingTcpPacket.Header.Flags == header.TCPFlagSyn|header.TCPFlagAck {
				//syn, ack received
				newConn.State = socket.ESTABLISHED
				newConn.AckN = incomingTcpPacket.Header.SeqNum + 1
				newConn.LastByteRead = newConn.AckN - 1
				newConn.ReceiverWindow = incomingTcpPacket.Header.WindowSize
				ackTcpPacket := newConn.CreateTCPPacket(newConn.SeqN, []byte{})
				//send ack
			    SendPacket(nodeInfo, dest, packet.TCP_PROTOCOL, packet.DEFAULT_TTL, ackTcpPacket.Marshal(), packet.Int2ip(newConn.LocalIPAddress).String())
				return 1
			}
				
			//SYN, AcK not coming so resend SYN
		case <-time.After(time.Second * time.Duration(timeOutMap[numReTransmit])):
			// timeout
			fmt.Printf("trying attempt: %d\n", numReTransmit)
			if numReTransmit == 3 {
				return -1
			} else {
				numReTransmit += 1
				SendPacket(nodeInfo, dest, packet.TCP_PROTOCOL, packet.DEFAULT_TTL, payload, packet.Int2ip(newConn.LocalIPAddress).String())
			}
		}
	}

}

/*
* Function that gets called whenever a socket receive a Fin from the other side. 
* This is going to be executed on a different goroutine for it to be non-blocking
* The flow is as follows:
*
* (1) It recevies a [Fin, Ack] from the other end -> AcK that (close-wait)
* (2) Wait until we also call close on our side (via sd command)
* (3) After we receive the signal that we are done through FinChan and there's no more data left in the 
*     SendBuffer 
* (4) Send [Fin, Ack] of our own -> (last-ack)
* (5) Wait for the Ack to come back from the other end
* (6) Close the conn by removing the entry from the sockTable (closed)
*
* @param nodeInfo : Information about this node
* @param connToClose : connection that we want to close
* @paaram iniPac: TcpPacket received that initiated the closing process
 */
func PassiveClose(nodeInfo *info.NodeInfo, connToClose *socket.VTCPConn, iniPac *packet.TcpPacket){
	waitTime, _ := time.ParseDuration("2s")

	connToClose.State = socket.CLOSE_WAIT
	connToClose.SeqN = iniPac.Header.AckNum
	connToClose.AckN = iniPac.Header.SeqNum + 1
	outgoingTcpPacket := connToClose.CreateTCPPacket(connToClose.SeqN, []byte{})
	//send Ack for the Fin, Ack received from the active closer
	connToClose.SendPacketChan <- &packet.SendPacketRequest{
		Dest:                packet.Int2ip(connToClose.RemoteIPAddress).String(),
		Proto:               packet.TCP_PROTOCOL,
		TTL:                 packet.DEFAULT_TTL,
		Payload:             outgoingTcpPacket.Marshal(),
		OverwriteSrcAddress: packet.Int2ip(connToClose.LocalIPAddress).String(),
	}

	timeOutMap := map[int]int{0: 2, 1: 4, 2: 6, 3: 8}
	numReTransmitAcK := 0

	ackLoop:
	for {
		select {
			//if you receive Fin, AcK from the other end
		case <- connToClose.PacketChan:
			//only true if "q" is typed
			if connToClose.IsTerm {
				curTime := time.Now()
				//if more than 2s has elasped, just terminate (this is when the user typed in "q" cmd)
				if curTime.Sub(connToClose.TermStart) > waitTime {
					nodeInfo.SocketWaitGroup.Done()
					break
				}
			}
			// timeout
			fmt.Printf("> trying attempt: %d\n> ", numReTransmitAcK)
			if numReTransmitAcK == 3 {
				nodeInfo.PrintChan <- "> v_shutdown() exceeded retransmission attempts\n> "
				return
			} else {
				numReTransmitAcK += 1
				connToClose.SendPacketChan <- &packet.SendPacketRequest{
					Dest:                packet.Int2ip(connToClose.RemoteIPAddress).String(),
					Proto:               packet.TCP_PROTOCOL,
					TTL:                 packet.DEFAULT_TTL,
					Payload:             outgoingTcpPacket.Marshal(),
					OverwriteSrcAddress: packet.Int2ip(connToClose.LocalIPAddress).String(),
				}
			} 
			//hang until active close on this side too
		case <- connToClose.FinChan:
			break ackLoop
		}
	}

	//make sure nothing is left to send
	for {

		//only true if "q" is typed
		if connToClose.IsTerm {
			curTime := time.Now()
			//if more than 2s has elasped, just terminate (this is when the user typed in "q" cmd)
			if curTime.Sub(connToClose.TermStart) > waitTime {
				nodeInfo.SocketWaitGroup.Done()
				return
			}
		}

		if connToClose.TimeToFin(){
			break;
		}

		connToClose.RetransmissionChan <- true
		connToClose.TriggerSendChan <- true
	}

	//after all is sent and we recieve ack for them, proceed to send Fin, Ack
	connToClose.State = socket.LAST_ACK
	outgoingTcpPacket = connToClose.CreateTCPPacket(connToClose.SeqN, []byte{})
	//send Fin, Ack
	connToClose.SendPacketChan <- &packet.SendPacketRequest{
		Dest:                packet.Int2ip(connToClose.RemoteIPAddress).String(),
		Proto:               packet.TCP_PROTOCOL,
		TTL:                 packet.DEFAULT_TTL,
		Payload:             outgoingTcpPacket.Marshal(),
		OverwriteSrcAddress: packet.Int2ip(connToClose.LocalIPAddress).String(),
	}

	connToClose.FINAckN = connToClose.AckN
	numReTransmit := 0

	retransmissionLoop:
	for {
		select {
		case packet := <- connToClose.PacketChan:
			if packet.Header.Flags == header.TCPFlagAck {
				connToClose.State = socket.CLOSED
			}
			nodeInfo.SocketWaitGroup.Done()
			if !connToClose.IsTerm {
				nodeInfo.PrintChan <- "v_shutdown() returned 0\n> "
			} 
			break retransmissionLoop
		case <-time.After(time.Second * time.Duration(timeOutMap[numReTransmit])):
			//only true if "q" is typed
			if connToClose.IsTerm {
				curTime := time.Now()
				//if more than 2s has elasped, just terminate (this is when the user typed in "q" cmd)
				if curTime.Sub(connToClose.TermStart) > waitTime {
					nodeInfo.SocketWaitGroup.Done()
					break
				}
			}
			// timeout
			fmt.Printf("> trying attempt: %d\n>", numReTransmit)
			if numReTransmit == 3 {
				nodeInfo.PrintChan <- "> v_shutdown() exceeded retransmission attempts\n> "
				return
			} else {
				numReTransmit += 1
				connToClose.SendPacketChan <- &packet.SendPacketRequest{
					Dest:                packet.Int2ip(connToClose.RemoteIPAddress).String(),
					Proto:               packet.TCP_PROTOCOL,
					TTL:                 packet.DEFAULT_TTL,
					Payload:             outgoingTcpPacket.Marshal(),
					OverwriteSrcAddress: packet.Int2ip(connToClose.LocalIPAddress).String(),
				}
			} 
		}
	}
}

/*
* Function that gets called whenever we call sd for the *first time*
* This is going to be executed on a different goroutine for it to be non-blocking
* The flow is as follows:
*
* (1) It sends a [Fin, Ack] to the other end and wait for Ack -> Fin-wait-2
* (2) Wait until we get a [Fin, Ack] from the other side too -> time-wait
* (3) Send [Ack] for the received [Fin, Ack] 
* (4) After 2 MSL, close the conn
*
* @param nodeInfo : Information about this node
* @param connToClose : connection that we want to close
 */
func ActiveClose(nodeInfo *info.NodeInfo, connToClose *socket.VTCPConn) {

	waitTime, _ := time.ParseDuration("2s")

	//hang until we are done retransmitting packets that need to be retransmitted
	for {
		//only true if "q" is typed
		if connToClose.IsTerm {
			curTime := time.Now()
			//if more than 2s has elasped, just terminate (this is when the user typed in "q" cmd)
			if curTime.Sub(connToClose.TermStart) > waitTime {
				nodeInfo.SocketWaitGroup.Done()
				break
			}
		}
		if connToClose.TimeToFin() {
			break;
		}

		connToClose.RetransmissionChan <- true
		connToClose.TriggerSendChan <- true
	}

	//when we get here, we are guaranteed to have received all the AcKs needed

	//construct the tcp packet payload with FIN, Ack
	connToClose.State = socket.FIN_WAIT_1
	outgoingTcpPacket := connToClose.CreateTCPPacket(connToClose.SeqN, []byte{})

	connToClose.SendPacketChan <- &packet.SendPacketRequest{
		Dest:                packet.Int2ip(connToClose.RemoteIPAddress).String(),
		Proto:               packet.TCP_PROTOCOL,
		TTL:                 packet.DEFAULT_TTL,
		Payload:             outgoingTcpPacket.Marshal(),
		OverwriteSrcAddress: packet.Int2ip(connToClose.LocalIPAddress).String(),
	}

	connToClose.FINAckN = connToClose.AckN
	timeOutMap := map[int]int{0: 2, 1: 4, 2: 6, 3: 8}
	numReTransmit := 0
	numAckReTransmit := 0

	//hang until it is AcK
	retransmissionLoop:
	for {
		select {
			case pac := <- connToClose.PacketChan:
				//recv AcK  (normal case)
			if pac.Header.Flags == header.TCPFlagAck {
				connToClose.State = socket.FIN_WAIT_2
			} 
			
			//if "q" is typed, don't wait for other party to send Fin, AcK
			if connToClose.IsTerm {
				nodeInfo.SocketWaitGroup.Done()
				break retransmissionLoop
			}

			//hang until we get a Fin, AcK from other side. Have this because when you "q", this blocks
			innerL:
			for {
				select {
				case pac = <- connToClose.PacketChan:
					break innerL
				
				case <- time.After(1*time.Second):
					if connToClose.IsTerm {
						nodeInfo.SocketWaitGroup.Done()
						break retransmissionLoop
					}
				}
			}

			//we get a Fin, Ack from the other side, Ack that
			connToClose.State = socket.TIME_WAIT
			connToClose.SeqN = pac.Header.AckNum
			connToClose.AckN = pac.Header.SeqNum + 1
			outgoingTcpPacket = connToClose.CreateTCPPacket(connToClose.SeqN, []byte{})

			connToClose.SendPacketChan <- &packet.SendPacketRequest{
				Dest:                packet.Int2ip(connToClose.RemoteIPAddress).String(),
				Proto:               packet.TCP_PROTOCOL,
				TTL:                 packet.DEFAULT_TTL,
				Payload:             outgoingTcpPacket.Marshal(),
				OverwriteSrcAddress: packet.Int2ip(connToClose.LocalIPAddress).String(),
			}

			//time.Sleep(10 * time.Second)
			timeOutDur, _ := time.ParseDuration("10s")
			timeToStop := (time.Now()).Add(timeOutDur)

			for {
				select {
					//out AcK was dropped, so we receive Fin, Ack again
					case  <- connToClose.PacketChan:
						//reset MSL timer
						timeToStop = (time.Now()).Add(timeOutDur)
						//AcK again
						if numAckReTransmit == 3 {
							nodeInfo.PrintChan <- "v_shutdown() exceeded retransmission attempts\n> "
							return
						} else {
							numAckReTransmit += 1
							connToClose.SendPacketChan <- &packet.SendPacketRequest{
								Dest:                packet.Int2ip(connToClose.RemoteIPAddress).String(),
								Proto:               packet.TCP_PROTOCOL,
								TTL:                 packet.DEFAULT_TTL,
								Payload:             outgoingTcpPacket.Marshal(),
								OverwriteSrcAddress: packet.Int2ip(connToClose.LocalIPAddress).String(),
							}
						}
						//has 2 MSL passed yet?
					case <- time.After(time.Second * 1):
						if (time.Now()).After(timeToStop) {
							connToClose.State = socket.CLOSED
							nodeInfo.SocketWaitGroup.Done()
							if !connToClose.IsTerm {
								nodeInfo.PrintChan <- "v_shutdown() returned 0\n> "
							}
							break retransmissionLoop
						}
				}
			}
			//retransmit
			case <-time.After(time.Second * time.Duration(timeOutMap[numReTransmit])):
				//only true if "q" is typed
			if connToClose.IsTerm {
				curTime := time.Now()
				//if more than 2s has elasped, just terminate (this is when the user typed in "q" cmd)
				if curTime.Sub(connToClose.TermStart) > waitTime {
					nodeInfo.SocketWaitGroup.Done()
					break retransmissionLoop
				}
			}
			// timeout
			fmt.Printf("trying attempt: %d\n", numReTransmit)
			if numReTransmit == 3 {
				nodeInfo.PrintChan <- "v_shutdown() exceeded retransmission attempts\n> "
				return
			} else {
				numReTransmit += 1
				connToClose.SendPacketChan <- &packet.SendPacketRequest{
					Dest:                packet.Int2ip(connToClose.RemoteIPAddress).String(),
					Proto:               packet.TCP_PROTOCOL,
					TTL:                 packet.DEFAULT_TTL,
					Payload:             outgoingTcpPacket.Marshal(),
					OverwriteSrcAddress: packet.Int2ip(connToClose.LocalIPAddress).String(),
				}
			}
		}
	}
}
/*
* Function that handles incoming TCP packets
* 1. First we check the normal sockets
* 	- SYN, AcK will be received here -> entry becomes estab, send AcK to listening conn
*   - AcK will be received here -> make the entry estab
*   - Data transfer
* 2. Second we check the listening sockets
* 	- SYN event will happen in here
*     - we create a new entry for the incoming connection on the listening side
 */
func TCPPacketHandler(new_packet *packet.IpPacket, nodeInfo *info.NodeInfo) {
	tcpPacket := packet.UnmarshalTcpPacket(new_packet.Payload)

	//Get the IP Address Int and Ports reversed
	remoteIpInt, err := packet.Ip2int(new_packet.Header.Src)
	if err != nil {
		log.Fatalln("Converting ip to int: ", err)
	}
	localIpInt, err := packet.Ip2int(new_packet.Header.Dst)
	if err != nil {
		log.Fatalln("Converting ip to int: ", err)
	}
	localPort := tcpPacket.Header.DstPort
	remotePort := tcpPacket.Header.SrcPort

	//Construct the identifier
	socketIdentifier := &socket.SocketIdentifier{
		LocalIPAddress:  localIpInt,
		LocalPort:       localPort,
		RemoteIPAddress: remoteIpInt,
		RemotePort:      remotePort,
	}

	state := tcpPacket.Header.Flags
	var exist bool = false
	var sockConn *socket.VTCPConn = &socket.VTCPConn{}

	//Find in the normal conns
	for _, entry := range nodeInfo.SocketTable.SockTable {
		if IsMatchSocket(entry, socketIdentifier) {
			sockConn = entry
			exist = true
			break
		}
	}

	_, ok := nodeInfo.SocketTable.PORT_TO_SID[localPort]

	//If found
	if exist {
		if state == header.TCPFlagSyn|header.TCPFlagAck {
			if sockConn.State == socket.SYN_SENT {
			// RECEIVING SYN+ACK (2ND STEP OF HANDSHAKE)
				sockConn.PacketChan <- tcpPacket
				//retransmitted SYN, AcK
			} else if sockConn.State == socket.ESTABLISHED {
				ackTcpPacket := sockConn.CreateTCPPacket(sockConn.SeqN, []byte{})
				//send ack
			    SendPacket(
					nodeInfo, 
					packet.Int2ip(sockConn.RemoteIPAddress).String(), 
					packet.TCP_PROTOCOL, 
					packet.DEFAULT_TTL, 
					ackTcpPacket.Marshal(), 
					packet.Int2ip(sockConn.LocalIPAddress).String(),
				)
			}
		} else if ok && sockConn.State == socket.SYN_RECEIVED {
			// has listener and socket in the middle of handshake
			// RECEIVING ACK (3RD STEP OF HANDSHAKE)
			sockConn.PacketChan <- tcpPacket
		} else if state == header.TCPFlagFin|header.TCPFlagAck {
			//(Passive Closer) Fin, Ack / Ack
			//the other end wants to close
			if sockConn.State == socket.ESTABLISHED {
				go PassiveClose(nodeInfo, sockConn, tcpPacket)
				return
			//(Activer Closer) transition from FIN_WAIT_2 -> TIME-WAIT
			//the other end is ready to close too. 
			} else if sockConn.State == socket.FIN_WAIT_2 {
				sockConn.PacketChan <- tcpPacket
				return
			}
		} else {
			//if we are waiting for AcK for the Fin and the packet SeqN and FinAcKN match
			if (sockConn.State == socket.FIN_WAIT_1) && (tcpPacket.Header.SeqNum == sockConn.FINAckN) {
				//AcK for the Fin, AcK the active closer sent
				sockConn.PacketChan <- tcpPacket
			} else if (sockConn.State == socket.LAST_ACK) && (tcpPacket.Header.SeqNum == sockConn.FINAckN){
				//Ack for the Fin, Ack the passive closer sent
				sockConn.PacketChan <- tcpPacket
			} else {
				//data transfer
				sockConn.HandlePacket(tcpPacket)
			}
		}
	} else {
		//if not found, check the listening socks
		SID, ok := nodeInfo.SocketTable.PORT_TO_SID[localPort]
		//if we are listening on that port
		if ok {
			listener := nodeInfo.SocketTable.ListeningSocks[SID]
			//if it is an SYN event, create an entry (= new TCB)
			if state == header.TCPFlagSyn {
				listener.ClientInfoChan <- socket.TCPClientInfo{
					Identifier: socketIdentifier,
					Header:     tcpPacket.Header,
				}
			}
		} else {
			return
		}
	}
}
