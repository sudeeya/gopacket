package layers

import (
	"encoding/binary"
	"fmt"
	"net"

	"github.com/google/gopacket"
)

// Potential values for IPCP.Code.
const (
	IPCPOffer   = 1
	IPCPSuccess = 2
	IPCPFailure = 3
)

// IPCP is the layer for experimental IP Configuration Protocol.
type IPCP struct {
	BaseLayer
	Code       uint8
	Length     uint16
	Address    net.IP
	SubnetMask net.IPMask
	Message    []byte
}

// LayerType returns LayerTypeIPCP.
func (ipcp *IPCP) LayerType() gopacket.LayerType {
	return LayerTypeIPCP
}

// DecodeFromBytes decodes the given bytes into this layer.
func (ipcp *IPCP) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
	if len(data) < 3 {
		df.SetTruncated()
		return fmt.Errorf("IPCP length %d too short", len(data))
	}

	ipcp.Code = data[0]
	ipcp.Length = binary.BigEndian.Uint16(data[1:3])
	if len(data) < int(ipcp.Length) {
		df.SetTruncated()
		return fmt.Errorf("IPCP length %d too short, %d expected", len(data), ipcp.Length)
	}
	switch ipcp.Code {
	case IPCPOffer:
		ipcp.Address = net.IPv4(data[3], data[4], data[5], data[6]).To4()
		ipcp.SubnetMask = net.IPv4Mask(data[7], data[8], data[9], data[10])
		ipcp.Message = nil
	case IPCPSuccess, IPCPFailure:
		ipcp.Message = data[3:]
		ipcp.Address = nil
		ipcp.SubnetMask = nil
	default:
		return fmt.Errorf("invalid IPCP code %d", ipcp.Code)
	}
	ipcp.Contents = data[:ipcp.Length]
	ipcp.Payload = data[ipcp.Length:]

	return nil
}

// SerializeTo writes the serialized form of this layer into the
// SerializationBuffer, implementing gopacket.SerializableLayer.
// See the docs for gopacket.SerializableLayer for more info.
func (ipcp *IPCP) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	size := 3
	switch ipcp.Code {
	case IPCPOffer:
		if ipcp.Message != nil {
			return fmt.Errorf("packet with IPCP code %d cannot contain Message field", ipcp.Code)
		}
		size += 8
	case IPCPSuccess, IPCPFailure:
		if ipcp.Address != nil || ipcp.SubnetMask != nil {
			return fmt.Errorf("packet with IPCP code %d cannot contain Address and SubnetMask fields", ipcp.Code)
		}
		size += len(ipcp.Message)
	default:
		return fmt.Errorf("invalid IPCP code %d", ipcp.Code)
	}

	bytes, err := b.PrependBytes(size)
	if err != nil {
		return err
	}

	if opts.FixLengths {
		ipcp.Length = uint16(size)
	}

	bytes[0] = ipcp.Code
	binary.BigEndian.PutUint16(bytes[1:], ipcp.Length)
	switch ipcp.Code {
	case IPCPOffer:
		copy(bytes[3:7], ipcp.Address.To4())
		copy(bytes[7:11], ipcp.SubnetMask)
	case IPCPSuccess, IPCPFailure:
		copy(bytes[3:], ipcp.Message)
	}

	return nil
}

// CanDecode returns the set of layer types that this DecodingLayer can decode.
func (ipcp *IPCP) CanDecode() gopacket.LayerClass {
	return LayerTypeIPCP
}

// NextLayerType returns the layer type contained by this DecodingLayer.
func (ipcp *IPCP) NextLayerType() gopacket.LayerType {
	return gopacket.LayerTypeZero
}

func decodeIPCP(data []byte, p gopacket.PacketBuilder) error {
	ipcp := &IPCP{}
	return decodingLayerDecoder(ipcp, data, p)
}
