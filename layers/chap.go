package layers

import (
	"encoding/binary"
	"fmt"

	"github.com/google/gopacket"
)

// Potential values for CHAP.Code.
const (
	CHAPChallenge = 1
	CHAPResponse  = 2
	CHAPSuccess   = 3
	CHAPFailure   = 4
)

// CHAP is the layer for Challenge Handshake Authentication Protocol.
type CHAP struct {
	BaseLayer
	Code       uint8
	Identifier uint8
	Length     uint16
	ValueSize  uint8
	Value      []byte
	Name       []byte
	Message    []byte
}

// LayerType returns LayerTypeCHAP.
func (chap *CHAP) LayerType() gopacket.LayerType {
	return LayerTypeCHAP
}

// DecodeFromBytes decodes the given bytes into this layer.
func (chap *CHAP) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
	if len(data) < 4 {
		df.SetTruncated()
		return fmt.Errorf("CHAP length %d too short", len(data))
	}

	chap.Code = data[0]
	chap.Identifier = data[1]
	chap.Length = binary.BigEndian.Uint16(data[2:4])
	if len(data) < int(chap.Length) {
		df.SetTruncated()
		return fmt.Errorf("CHAP length %d too short, %d expected", len(data), chap.Length)
	}
	switch chap.Code {
	case CHAPChallenge, CHAPResponse:
		chap.ValueSize = data[4]
		if len(data)-5 < int(chap.ValueSize) {
			df.SetTruncated()
			return fmt.Errorf("Value field length too short, %d expected", chap.ValueSize)
		}
		chap.Value = data[5 : 5+chap.ValueSize]
		chap.Name = data[5+chap.ValueSize:]
		chap.Message = nil
	case CHAPSuccess, CHAPFailure:
		chap.Message = data[4:]
		chap.ValueSize = 0
		chap.Value = nil
		chap.Name = nil
	default:
		return fmt.Errorf("invalid CHAP code %d", chap.Code)
	}
	chap.Contents = data[:chap.Length]
	chap.Payload = data[chap.Length:]

	return nil
}

// SerializeTo writes the serialized form of this layer into the
// SerializationBuffer, implementing gopacket.SerializableLayer.
// See the docs for gopacket.SerializableLayer for more info.
func (chap *CHAP) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	size := 4
	switch chap.Code {
	case CHAPChallenge, CHAPResponse:
		if chap.Message != nil {
			return fmt.Errorf("packet with CHAP code %d cannot contain Message field", chap.Code)
		}
		size += 1 + len(chap.Value) + len(chap.Name)
	case CHAPSuccess, CHAPFailure:
		if chap.Value != nil || chap.Name != nil {
			return fmt.Errorf("packet with CHAP code %d cannot contain Value and Name fields", chap.Code)
		}
		size += len(chap.Message)
	default:
		return fmt.Errorf("invalid CHAP code %d", chap.Code)
	}

	bytes, err := b.PrependBytes(size)
	if err != nil {
		return err
	}

	if opts.FixLengths {
		chap.Length = uint16(size)
	}

	bytes[0] = chap.Code
	bytes[1] = chap.Identifier
	binary.BigEndian.PutUint16(bytes[2:], chap.Length)
	switch chap.Code {
	case CHAPChallenge, CHAPResponse:
		bytes[4] = chap.ValueSize
		var valueAndName []byte
		valueAndName = append(valueAndName, chap.Value...)
		valueAndName = append(valueAndName, chap.Name...)
		copy(bytes[5:], valueAndName)
	case CHAPSuccess, CHAPFailure:
		copy(bytes[4:], chap.Message)
	}

	return nil
}

// CanDecode returns the set of layer types that this DecodingLayer can decode.
func (chap *CHAP) CanDecode() gopacket.LayerClass {
	return LayerTypeCHAP
}

// NextLayerType returns the layer type contained by this DecodingLayer.
func (chap *CHAP) NextLayerType() gopacket.LayerType {
	return gopacket.LayerTypeZero
}

func decodeCHAP(data []byte, p gopacket.PacketBuilder) error {
	chap := &CHAP{}
	return decodingLayerDecoder(chap, data, p)
}
