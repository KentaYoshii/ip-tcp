package packet

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"net"
	"sort"

	"github.com/google/netstack/tcpip/header"
	"github.com/praserx/ipconv"
	"golang.org/x/net/ipv4"
)

const (
	MAX_UINT32    = 4294967295
	MAX_HOP_COST  = 16
	TEST_PROTOCOL = 0
	RIP_PROTOCOL  = 200
	ICMP_PROTOCOL = 1
	TCP_PROTOCOL  = 6
	MSS           = 1400
	DEFAULT_TTL   = 16
	IP_HDR_LEN    = ipv4.HeaderLen
)

/*
* Struct for representing each packet
*
* Header: ipv4.Header for representing our IP packet Header
* Payload: string in byte slice for Test protocol/RipPacket in byte slice for RIP protocol
 */
type IpPacket struct {
	Header  *ipv4.Header
	Payload []byte
}

/*
* Struct for representing each Hop
*
* Cost: the cost to get to this router
* Address: the address for this router
* Mask: the mask for the network Ip
* Sender: the nextHop's IP Address to get to this destinaiton
 */
type HopData struct {
	Cost    uint32 //4b
	Address uint32 //4b
	Mask    uint32 //4b
}

/*
* Our Struct for representing all the entries in our RoundTable
*
* Command: 0 or 1 (0 for exchanging init info, 1 for response)
* Num_entries: number of entries we are sending over
* Entries: stores our entries
 */
type RipPacket struct {
	Command     uint16     //2b
	Num_entries uint16     //2b
	Entries     []*HopData //16 ea
}

/*
* Function that converts IPv4 Addr to uint32
*
* @param ip: net.IP's IPv4 Address we would like to convert to uint32
* @return uint32: ip after conversion to uint32
* @return error: != nil, if error occurs after the conversoin
 */
func Ip2int(ip net.IP) (uint32, error) {
	return ipconv.IPv4ToInt(ip)
}

/*
* Function that converts uint32 to IPv4 Addr
*
* @param nn: uint32 number that we would like to convert to net.IP
* @param net.IP: IPv4 Address corresponding to the uint32 number
 */
func Int2ip(nn uint32) net.IP {
	return ipconv.IntToIPv4(nn)
}

/*
* Function that computes the checksum.
* We will use this for validation before forwarding
* (This is using the prof.'s implementation)
*
* @param b : bytes that we want to validate
*
* @return uint16 : hashed bytes
 */
func ComputeChecksum(b []byte) uint16 {
	checksum := header.Checksum(b, 0)
	checksumInv := checksum ^ 0xffff
	return checksumInv
}

/*
* Function that marshals IpPacket struct into a byte slice
* The header bytes are followed by payload bytes
*
* @return []bytes bytes we will write to our nextHop UDPConn
 */
func (ipPacket *IpPacket) Marshal() []byte {
	// recompute the bytes after setting the checksum field
	headerBytes, err := ipPacket.Header.Marshal()
	if err != nil {
		log.Fatalln("Error marshalling header:  ", err)
	}
	//init the "packet" to be header_sz + payload_sz
	bytesToSend := make([]byte, 0, len(headerBytes)+len(ipPacket.Payload))
	//header bytes first
	bytesToSend = append(bytesToSend, headerBytes...)
	//then append the payload bytes
	bytesToSend = append(bytesToSend, ipPacket.Payload...)

	return bytesToSend
}

/*
* Function that unmarshals IpPacket by calling the ParseHeader() in ipv4 package
*
* @return *IpPacket : IpPacket struct object created out of the bytes in the buffer
 */
func UnmarshalIpPacket(buffer []byte) (packet *IpPacket) {
	hdr, err := ipv4.ParseHeader(buffer)
	if err != nil {
		fmt.Println("Error parsing header", err)
	}

	headerSize := hdr.Len
	message := buffer[headerSize:hdr.TotalLen]
	new_packet := &IpPacket{
		Header:  hdr,
		Payload: message,
	}
	return new_packet

}

/*
* Function that unmarshals bytes and return our RipPacket struct
*
* @param payload: bytes to unmarshal
 */
func UnmarshalRipPacket(payload []byte) *RipPacket {
	//first 2 bytes is Command
	command := binary.BigEndian.Uint16(payload[0:2])
	//next 2 bytes is Num_entries
	num_entries := binary.BigEndian.Uint16(payload[2:4])
	//remaining is our Entries ([]HopData)
	entries_b := payload[4:]
	entries := make([]*HopData, 0)
	for i := 0; i < int(num_entries); i++ {
		//each HopData is size 12
		var offset = i * 12
		curEntry := &HopData{
			Cost:    binary.BigEndian.Uint32(entries_b[(0 + offset):(4 + offset)]),
			Address: binary.BigEndian.Uint32(entries_b[(4 + offset):(8 + offset)]),
			Mask:    binary.BigEndian.Uint32(entries_b[(8 + offset):(12 + offset)]),
		}
		entries = append(entries, curEntry)
	}
	//create the struct with unmarshalled values
	new_rip := &RipPacket{
		Command:     command,
		Num_entries: num_entries,
		Entries:     entries,
	}
	return new_rip

}

/*
* Function that gets called when a router receives a packet.
* This function validates the packet by checking
* 	(1) Whether TTL is 0 or not
* 	(2) Whether Checksum computed over the Header matches
*	(3) Whether TCP checksum is matching
* @return error : Raised if the packet is Invalid (Checksum or TTL)
 */
func (packet *IpPacket) ValidatePacket() error {
	//====================Validate IP packet======================
	hdr := packet.Header
	if hdr.TTL == 0 {
		return errors.New("TTL")
	}
	pre_Checksum := hdr.Checksum
	hdr.Checksum = 0
	headerBytes, err := hdr.Marshal()
	if err != nil {
		log.Fatalln("Error marshalling header:  ", err)
	}
	aft_Checksum := int(ComputeChecksum(headerBytes))
	if pre_Checksum != aft_Checksum {
		return errors.New("IP Checksum")
	}

	//===================Validate TCP packet=======================
	if packet.Header.Protocol == TCP_PROTOCOL {
		tcpHeaderAndData := packet.Payload
		tcpHdr := ParseTCPHeader(tcpHeaderAndData)
		tcpPayload := tcpHeaderAndData[tcpHdr.DataOffset:]
		tcpChecksumFromHeader := tcpHdr.Checksum
		tcpHdr.Checksum = 0
		tcpComputedChecksum := ComputeTCPChecksum(tcpHdr, hdr.Src, hdr.Dst, tcpPayload)
		if tcpChecksumFromHeader != tcpComputedChecksum {
			return errors.New("TCP Checksum")
		}
	}

	//once we know the checksum did not change
	//update TTL for packet forwarding
	hdr.TTL -= 1
	//recompute checksum with the new TTL value
	headerBytes, err = hdr.Marshal()
	if err != nil {
		log.Fatalln("Error marshalling header:  ", err)
	}
	new_Checksum := int(ComputeChecksum(headerBytes))
	//reassign
	hdr.Checksum = new_Checksum

	return nil
}

/*
* Helper function thag gets the uint32 representation of the IP addresses
 */
func (pc *IpPacket) GetIPAddrInt() (uint32, uint32) {
	LocalIPAddressInt, err := Ip2int(pc.Header.Dst)
	if err != nil {
		log.Panicln("Error converting ip addr 2 int: ", err)
	}
	RemoteIPAddressInt, err := Ip2int(pc.Header.Src)
	if err != nil {
		log.Panicln("Error converting ip addr 2 int: ", err)
	}
	return LocalIPAddressInt, RemoteIPAddressInt
}

/*
* Function that marshals RipPacket
* It writes Command, Num_entries, and all the HopData to the buffer
*
* @return []byte: RipPacket converted to byte slice
 */
func (rip *RipPacket) Marshal() []byte {
	buf := new(bytes.Buffer)
	err := binary.Write(buf, binary.BigEndian, rip.Command)
	if err != nil {
		log.Fatalln("Marshal RIP Command: ", err)
	}
	err = binary.Write(buf, binary.BigEndian, rip.Num_entries)
	if err != nil {
		log.Fatalln("Marshal RIP Num_entries: ", err)
	}
	// Command == 1 -> request for routing information
	if rip.Command == 1 {
		return buf.Bytes()
	} else {
		// Command == 2 -> response to a request
		//for each HopData
		for _, entry := range rip.Entries {
			err = binary.Write(buf, binary.BigEndian, entry.Cost)
			if err != nil {
				log.Fatalln("Marshal RIP Entry (Cost): ", err)
			}
			err = binary.Write(buf, binary.BigEndian, entry.Address)
			if err != nil {
				log.Fatalln("Marshal RIP Entry (Address): ", err)
			}
			err = binary.Write(buf, binary.BigEndian, entry.Mask)
			if err != nil {
				log.Fatalln("Marshal RIP Entry (Mask): ", err)
			}
		}
		return buf.Bytes()
	}
}

/*
* Helper for debugging :)
*
* Sample output
*
* -----RIP Packet Receive-----
* Rec from       : 192.168.0.2
* <entry num> <destAddr> <nexthopAddr> <cost>
*  Entry 0   192.168.0.1  192.168.0.1    1
*-----------------------------
*
* @return formatted output string
 */
func (packet *RipPacket) String(hdr *ipv4.Header) string {
	if packet.Command == 1 {
		outString := "\n-----RIP Packet Receive-----\n"
		outString += fmt.Sprintf("Rec from       : %s\n", hdr.Src.String())
		outString += "Request for Routing Information\n"
		outString += "-----------------------------\n"
		return outString
	} else {
		outString := "\n-----RIP Packet Receive-----\n"
		outString += fmt.Sprintf("Rec from       : %s\n", hdr.Src.String())
		outString += "Response for Routing Information Request\n"
		outString += "<entry num> <destAddr> <nexthopAddr> <cost>\n"
		entries := packet.Entries
		sort.Slice(entries, func(i, j int) bool {
			return entries[i].Cost < entries[j].Cost
		})
		for idx, entry := range entries {
			outString += fmt.Sprintf("  Entry %d   %s %s     %d\n", idx, Int2ip(entry.Address), hdr.Src.String(), entry.Cost)
		}
		outString += "-----------------------------\n"
		return outString
	}
}

/*
* Function that gets called when a router receives a packet that has protocol 0
* It observes the format specified in the handout
*
* Sample output
*
* ---Node received packet!---
* sourceIP       : 192.168.0.2
* destinationIP  : 192.168.0.1
* protocol       : 0
* payload length : 11
* payload        : hello world
* ---------------------------
*
* @return formatted string of packet
 */
func (packet *IpPacket) String() string {
	outString := "\n---Node received packet!---\n"
	outString += fmt.Sprintf("sourceIP       : %s\n", packet.Header.Src.String())
	outString += fmt.Sprintf("destinationIP  : %s\n", packet.Header.Dst.String())
	outString += fmt.Sprintf("protocol       : %d\n", packet.Header.Protocol)
	outString += fmt.Sprintf("payload length : %d\n", packet.Header.TotalLen-packet.Header.Len)
	outString += fmt.Sprintf("payload        : %s\n", string(packet.Payload))
	outString += "---------------------------\n"
	return outString
}

/*
* Function that constructs the IP Header for the packet we want to send
*
* @param src : src IPAddr
* @param dest : dest IPAddr
* @param msgLen : Payload size
* @param proto : protocol 200 or 0
* @return net.ipv4.Header
 */
func ConstructIPHeader(src string, dest string, msgLen int, proto int, ttl int) *ipv4.Header {
	hdr := &ipv4.Header{
		Version:  4,
		Len:      ipv4.HeaderLen,
		TOS:      0,
		TotalLen: ipv4.HeaderLen + msgLen,
		ID:       0,
		Flags:    0,
		FragOff:  0,
		TTL:      ttl,
		Protocol: proto,
		Checksum: 0,
		Src:      net.ParseIP(src),
		Dst:      net.ParseIP(dest),
		Options:  []byte{},
	}
	return hdr
}
