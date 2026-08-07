package dgpv1

import (
	"encoding/binary"
	"errors"
	"fmt"
)

const (
	// TLVHeaderSize is the encoded size of a DGPv1 TLV header.
	TLVHeaderSize = 3
	// MaxTLVValueSize is the largest value representable by the wire length.
	MaxTLVValueSize = 1<<16 - 1
)

var (
	ErrTLVTooShort       = errors.New("dgpv1: TLV too short")
	ErrTLVTruncated      = errors.New("dgpv1: truncated TLV")
	ErrTLVValueTooLarge  = errors.New("dgpv1: TLV value exceeds uint16 length")
	ErrTLVDecodeLimit    = errors.New("dgpv1: TLV input exceeds decode limit")
	ErrTLVInvalidPadding = errors.New("dgpv1: TLV padding must be zero")
)

// TLV is one application field. Value is owned by the TLV and does not alias
// caller input when constructed with NewTLV or decoded with DecodeTLVs.
type TLV struct {
	Type  uint8
	Value []byte
}

// NewTLV constructs a TLV and copies value.
func NewTLV(typ uint8, value []byte) (TLV, error) {
	if len(value) > MaxTLVValueSize {
		return TLV{}, fmt.Errorf("%w: got %d bytes", ErrTLVValueTooLarge, len(value))
	}
	return TLV{Type: typ, Value: append([]byte(nil), value...)}, nil
}

// EncodedLen returns the encoded length including zero alignment padding.
func (t TLV) EncodedLen() (int, error) {
	if len(t.Value) > MaxTLVValueSize {
		return 0, fmt.Errorf("%w: got %d bytes", ErrTLVValueTooLarge, len(t.Value))
	}
	return align4(TLVHeaderSize + len(t.Value)), nil
}

// MarshalBinary encodes t and zero-pads it to a 4-byte boundary.
func (t TLV) MarshalBinary() ([]byte, error) {
	n, err := t.EncodedLen()
	if err != nil {
		return nil, err
	}
	buf := make([]byte, n)
	buf[0] = t.Type
	binary.LittleEndian.PutUint16(buf[1:3], uint16(len(t.Value)))
	copy(buf[TLVHeaderSize:], t.Value)
	return buf, nil
}

// DecodeTLVs decodes exactly one TLV sequence of at most maxBytes bytes. It
// preserves unknown types and copies values so the result does not alias data.
// A non-positive maxBytes disables the caller limit.
func DecodeTLVs(data []byte, maxBytes int) ([]TLV, error) {
	if maxBytes > 0 && len(data) > maxBytes {
		return nil, fmt.Errorf("%w: got %d bytes, limit %d", ErrTLVDecodeLimit, len(data), maxBytes)
	}

	var out []TLV
	for offset := 0; offset < len(data); {
		remaining := len(data) - offset
		if remaining < TLVHeaderSize {
			return nil, fmt.Errorf("%w at offset %d: got %d header bytes", ErrTLVTooShort, offset, remaining)
		}
		valueLen := int(binary.LittleEndian.Uint16(data[offset+1 : offset+3]))
		unpadded := TLVHeaderSize + valueLen
		encoded := align4(unpadded)
		if remaining < unpadded {
			return nil, fmt.Errorf("%w at offset %d: value needs %d bytes, got %d", ErrTLVTruncated, offset, valueLen, remaining-TLVHeaderSize)
		}
		if remaining < encoded {
			return nil, fmt.Errorf("%w at offset %d: padding needs %d bytes, got %d", ErrTLVTruncated, offset, encoded-unpadded, remaining-unpadded)
		}
		for _, b := range data[offset+unpadded : offset+encoded] {
			if b != 0 {
				return nil, fmt.Errorf("%w at offset %d", ErrTLVInvalidPadding, offset)
			}
		}
		out = append(out, TLV{
			Type:  data[offset],
			Value: append([]byte(nil), data[offset+TLVHeaderSize:offset+unpadded]...),
		})
		offset += encoded
	}
	return out, nil
}

// EncodeTLVs encodes fields in order. Duplicate and unknown types are retained.
func EncodeTLVs(fields []TLV) ([]byte, error) {
	total := 0
	for _, field := range fields {
		n, err := field.EncodedLen()
		if err != nil {
			return nil, err
		}
		if total > int(^uint(0)>>1)-n {
			return nil, ErrTLVValueTooLarge
		}
		total += n
	}

	buf := make([]byte, 0, total)
	for _, field := range fields {
		encoded, err := field.MarshalBinary()
		if err != nil {
			return nil, err
		}
		buf = append(buf, encoded...)
	}
	return buf, nil
}

func align4(n int) int { return (n + 3) &^ 3 }
