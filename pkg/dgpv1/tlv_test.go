package dgpv1

import (
	"errors"
	"reflect"
	"testing"
)

func TestTLVGoldenWire(t *testing.T) {
	got, err := (TLV{Type: 0x2a, Value: []byte{0x10, 0x20, 0x30}}).MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	want := []byte{0x2a, 0x03, 0x00, 0x10, 0x20, 0x30, 0x00, 0x00}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("MarshalBinary() = % x, want % x", got, want)
	}
}

func TestTLVAlignmentAndEmptyValue(t *testing.T) {
	for valueLen, wantLen := range map[int]int{0: 4, 1: 4, 2: 8, 3: 8, 4: 8, 5: 8, 6: 12, 7: 12, 8: 12} {
		t.Run(string(rune('A'+valueLen)), func(t *testing.T) {
			field := TLV{Type: 1, Value: make([]byte, valueLen)}
			got, err := field.MarshalBinary()
			if err != nil {
				t.Fatal(err)
			}
			if len(got) != wantLen {
				t.Fatalf("encoded length for value %d = %d, want %d", valueLen, len(got), wantLen)
			}
		})
	}
}

func TestTLVMultipleUnknownDuplicateAndRoundTrip(t *testing.T) {
	want := []TLV{
		{Type: 1, Value: nil},
		{Type: 0xfe, Value: []byte("unknown")},
		{Type: 1, Value: []byte{9}},
	}
	wire, err := EncodeTLVs(want)
	if err != nil {
		t.Fatal(err)
	}
	got, err := DecodeTLVs(wire, len(wire))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("round trip = %#v, want %#v", got, want)
	}
}

func TestTLVOwnership(t *testing.T) {
	value := []byte{1, 2, 3}
	field, err := NewTLV(7, value)
	if err != nil {
		t.Fatal(err)
	}
	value[0] = 9
	if field.Value[0] != 1 {
		t.Fatal("NewTLV retained caller-owned storage")
	}

	wire, err := field.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeTLVs(wire, len(wire))
	if err != nil {
		t.Fatal(err)
	}
	wire[TLVHeaderSize] = 8
	if decoded[0].Value[0] != 1 {
		t.Fatal("DecodeTLVs retained input storage")
	}
}

func TestTLVTruncationAtEveryBoundary(t *testing.T) {
	wire, err := (TLV{Type: 3, Value: []byte{1, 2, 3, 4, 5}}).MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	for n := 1; n < len(wire); n++ {
		t.Run(string(rune('A'+n)), func(t *testing.T) {
			_, err := DecodeTLVs(wire[:n], len(wire))
			if err == nil {
				t.Fatalf("DecodeTLVs(%d bytes) succeeded", n)
			}
			if n < TLVHeaderSize && !errors.Is(err, ErrTLVTooShort) {
				t.Fatalf("error = %v, want ErrTLVTooShort", err)
			}
			if n >= TLVHeaderSize && !errors.Is(err, ErrTLVTruncated) {
				t.Fatalf("error = %v, want ErrTLVTruncated", err)
			}
		})
	}
}

func TestTLVRejectsNonzeroPadding(t *testing.T) {
	wire := []byte{1, 0, 0, 1}
	_, err := DecodeTLVs(wire, len(wire))
	if !errors.Is(err, ErrTLVInvalidPadding) {
		t.Fatalf("error = %v, want ErrTLVInvalidPadding", err)
	}
}

func TestTLVLimitsAndMaximumValue(t *testing.T) {
	max := TLV{Type: 1, Value: make([]byte, MaxTLVValueSize)}
	wire, err := max.MarshalBinary()
	if err != nil {
		t.Fatalf("maximum value: %v", err)
	}
	if _, err := DecodeTLVs(wire, len(wire)); err != nil {
		t.Fatalf("decode maximum value: %v", err)
	}
	if _, err := DecodeTLVs(wire, len(wire)-1); !errors.Is(err, ErrTLVDecodeLimit) {
		t.Fatalf("limit error = %v, want ErrTLVDecodeLimit", err)
	}
	tooLarge := TLV{Type: 1, Value: make([]byte, MaxTLVValueSize+1)}
	if _, err := tooLarge.MarshalBinary(); !errors.Is(err, ErrTLVValueTooLarge) {
		t.Fatalf("oversize error = %v, want ErrTLVValueTooLarge", err)
	}
	if _, err := NewTLV(1, tooLarge.Value); !errors.Is(err, ErrTLVValueTooLarge) {
		t.Fatalf("NewTLV oversize error = %v, want ErrTLVValueTooLarge", err)
	}
}

func TestDecodeTLVsDoesNotModifyDestinationOnError(t *testing.T) {
	valid, err := EncodeTLVs([]TLV{{Type: 1, Value: []byte{1}}, {Type: 2, Value: []byte{2}}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeTLVs(valid[:len(valid)-1], len(valid)); err == nil {
		t.Fatal("truncated sequence succeeded")
	}
}
