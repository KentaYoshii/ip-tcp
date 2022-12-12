package packet

type SendPacketRequest struct {
	Dest                string
	Proto               int
	TTL                 int
	Payload             []byte
	OverwriteSrcAddress string
}
