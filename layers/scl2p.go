package layers

import (
	"fmt"

	"github.com/google/gopacket"
)

// SCL2P is the layer for experimental Secure Configuration over L2 Protocol.
type SCL2P struct {
	BaseLayer
	Protocol SCL2PProtocol
}

// LayerType returns LayerTypeSCL2P.
func (scl2p *SCL2P) LayerType() gopacket.LayerType {
	return LayerTypeSCL2P
}

// DecodeFromBytes decodes the given bytes into this layer.
func (scl2p *SCL2P) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
	if len(data) < 1 {
		df.SetTruncated()
		return fmt.Errorf("SCL2P header length too short")
	}

	scl2p.Protocol = SCL2PProtocol(data[0])
	scl2p.Contents = data[:1]
	scl2p.Payload = data[1:]

	return nil
}

// SerializeTo writes the serialized form of this layer into the
// SerializationBuffer, implementing gopacket.SerializableLayer.
// See the docs for gopacket.SerializableLayer for more info.
func (scl2p *SCL2P) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	bytes, err := b.PrependBytes(1)
	if err != nil {
		return err
	}

	bytes[0] = byte(scl2p.Protocol)

	return nil
}

// CanDecode returns the set of layer types that this DecodingLayer can decode.
func (scl2p *SCL2P) CanDecode() gopacket.LayerClass {
	return LayerTypeSCL2P
}

// NextLayerType returns the layer type contained by this DecodingLayer.
func (scl2p *SCL2P) NextLayerType() gopacket.LayerType {
	return scl2p.Protocol.LayerType()
}

func decodeSCL2P(data []byte, p gopacket.PacketBuilder) error {
	scl2p := &SCL2P{}
	return decodingLayerDecoder(scl2p, data, p)
}
