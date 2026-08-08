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
	// MaxTLVSequenceSize bounds one TLV sequence to the protocol frame limit.
	MaxTLVSequenceSize = MaxFrameSize
	// MaxTLVElements is the most empty, aligned TLVs that fit in one sequence.
	MaxTLVElements = MaxTLVSequenceSize / 4
)

var (
	// ErrTLVTooShort indicates that input cannot contain a complete TLV header.
	ErrTLVTooShort = errors.New("dgpv1: TLV too short")
	// ErrTLVTruncated indicates that a TLV value or its alignment padding is incomplete.
	ErrTLVTruncated = errors.New("dgpv1: truncated TLV")
	// ErrTLVValueTooLarge indicates that a value exceeds the uint16 wire length.
	ErrTLVValueTooLarge = errors.New("dgpv1: TLV value exceeds uint16 length")
	// ErrTLVDecodeLimit indicates that input exceeds the caller's positive decode limit.
	ErrTLVDecodeLimit = errors.New("dgpv1: TLV input exceeds decode limit")
	// ErrTLVSequenceLimit indicates that an encoded sequence exceeds MaxTLVSequenceSize.
	ErrTLVSequenceLimit = errors.New("dgpv1: TLV sequence exceeds size limit")
	// ErrTLVElementLimit indicates that a sequence exceeds MaxTLVElements.
	ErrTLVElementLimit = errors.New("dgpv1: TLV sequence exceeds element limit")
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

// DecodeTLVs decodes exactly one TLV sequence. Protocol-wide size and element
// limits always apply; a positive maxBytes may impose a tighter caller limit.
// Unknown types are preserved, padding is ignored, and values are copied.
func DecodeTLVs(data []byte, maxBytes int) ([]TLV, error) {
	if len(data) > MaxTLVSequenceSize {
		return nil, fmt.Errorf("%w: got %d bytes, limit %d", ErrTLVSequenceLimit, len(data), MaxTLVSequenceSize)
	}
	if maxBytes > 0 && len(data) > maxBytes {
		return nil, fmt.Errorf("%w: got %d bytes, limit %d", ErrTLVDecodeLimit, len(data), maxBytes)
	}

	capacity := min(len(data)/4, MaxTLVElements)
	out := make([]TLV, 0, capacity)
	for offset := 0; offset < len(data); {
		if len(out) == MaxTLVElements {
			return nil, fmt.Errorf("%w: limit %d", ErrTLVElementLimit, MaxTLVElements)
		}
		remaining := len(data) - offset
		if remaining < TLVHeaderSize {
			return nil, fmt.Errorf("%w at offset %d: got %d header bytes", ErrTLVTooShort, offset, remaining)
		}

		valueLen := int(binary.LittleEndian.Uint16(data[offset+1 : offset+TLVHeaderSize]))
		if valueLen > remaining-TLVHeaderSize {
			return nil, fmt.Errorf("%w at offset %d: value needs %d bytes, got %d", ErrTLVTruncated, offset, valueLen, remaining-TLVHeaderSize)
		}
		unpadded := TLVHeaderSize + valueLen
		paddingLen := (4 - unpadded%4) % 4
		if paddingLen > remaining-unpadded {
			return nil, fmt.Errorf("%w at offset %d: padding needs %d bytes, got %d", ErrTLVTruncated, offset, paddingLen, remaining-unpadded)
		}
		encoded := unpadded + paddingLen
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
	if len(fields) > MaxTLVElements {
		return nil, fmt.Errorf("%w: got %d, limit %d", ErrTLVElementLimit, len(fields), MaxTLVElements)
	}

	total := 0
	for _, field := range fields {
		n, err := field.EncodedLen()
		if err != nil {
			return nil, err
		}
		if n > MaxTLVSequenceSize-total {
			return nil, fmt.Errorf("%w: limit %d", ErrTLVSequenceLimit, MaxTLVSequenceSize)
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
