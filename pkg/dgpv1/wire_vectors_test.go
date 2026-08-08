package dgpv1

import (
	"bytes"
	"encoding"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

const wireVectorSchema = "dgpv1-wire-v1"

type wireVectorFile struct {
	Schema  string       `json:"schema"`
	Vectors []wireVector `json:"vectors"`
}

type wireVector struct {
	Name        string `json:"name"`
	Kind        string `json:"kind"`
	MessageType *uint8 `json:"message_type,omitempty"`
	WireHex     string `json:"wire_hex"`
	Valid       bool   `json:"valid"`
	Error       string `json:"error,omitempty"`
}

func TestJSONWireVectors(t *testing.T) {
	paths, err := filepath.Glob(filepath.Join("testdata", "vectors", "*.json"))
	if err != nil {
		t.Fatal(err)
	}
	sort.Strings(paths)
	if len(paths) == 0 {
		t.Fatal("no JSON wire vector files found")
	}

	seen := make(map[string]string)
	for _, path := range paths {
		path := path
		t.Run(strings.TrimSuffix(filepath.Base(path), filepath.Ext(path)), func(t *testing.T) {
			file := loadWireVectorFile(t, path)
			for _, vector := range file.Vectors {
				vector := vector
				t.Run(vector.Name, func(t *testing.T) {
					if previous, ok := seen[vector.Name]; ok {
						t.Fatalf("duplicate vector name also appears in %s", previous)
					}
					seen[vector.Name] = path
					verifyWireVector(t, vector)
				})
			}
		})
	}
}

func loadWireVectorFile(t *testing.T, path string) wireVectorFile {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var file wireVectorFile
	if err := decoder.Decode(&file); err != nil {
		t.Fatalf("strict JSON decode: %v", err)
	}
	if err := requireJSONEOF(decoder); err != nil {
		t.Fatalf("strict JSON decode: %v", err)
	}
	if file.Schema != wireVectorSchema {
		t.Fatalf("schema = %q, want %q", file.Schema, wireVectorSchema)
	}
	if len(file.Vectors) == 0 {
		t.Fatal("vectors must not be empty")
	}
	return file
}

func requireJSONEOF(decoder *json.Decoder) error {
	var extra any
	if err := decoder.Decode(&extra); errors.Is(err, io.EOF) {
		return nil
	} else if err != nil {
		return err
	}
	return errors.New("trailing JSON value")
}

var vectorNamePattern = regexp.MustCompile(`^[a-z0-9]+(?:-[a-z0-9]+)*$`)

func verifyWireVector(t *testing.T, vector wireVector) {
	t.Helper()
	if !vectorNamePattern.MatchString(vector.Name) {
		t.Fatalf("invalid deterministic name %q", vector.Name)
	}
	if vector.WireHex != strings.ToLower(vector.WireHex) || len(vector.WireHex)%2 != 0 {
		t.Fatalf("wire_hex must be even-length lowercase hex")
	}
	wire, err := hex.DecodeString(vector.WireHex)
	if err != nil {
		t.Fatalf("wire_hex: %v", err)
	}
	if vector.Valid == (vector.Error != "") {
		t.Fatalf("valid vectors must omit error and malformed vectors must name one")
	}
	if vector.Kind == "message" && vector.MessageType == nil {
		t.Fatal("message vector requires message_type")
	}
	if vector.Kind != "message" && vector.MessageType != nil {
		t.Fatal("message_type is only valid for message vectors")
	}

	canonical, parseErr := parseWireVector(vector, wire)
	if !vector.Valid {
		want, ok := vectorErrors[vector.Error]
		if !ok {
			t.Fatalf("unknown typed error %q", vector.Error)
		}
		if !errors.Is(parseErr, want) {
			t.Fatalf("parse error = %v, want %s", parseErr, vector.Error)
		}
		return
	}
	if parseErr != nil {
		t.Fatalf("parse valid vector: %v", parseErr)
	}
	if !bytes.Equal(canonical, wire) {
		t.Fatalf("non-canonical valid vector: got %x, want %x", canonical, wire)
	}
}

func parseWireVector(vector wireVector, wire []byte) ([]byte, error) {
	switch vector.Kind {
	case "header":
		var header Header
		if err := header.UnmarshalBinary(wire); err != nil {
			return nil, err
		}
		if err := header.ValidateReceive(); err != nil {
			return nil, err
		}
		return header.marshalBinary(false)
	case "frame":
		var frame Frame
		if err := frame.UnmarshalBinary(wire); err != nil {
			return nil, err
		}
		if err := frame.ValidateReceive(); err != nil {
			return nil, err
		}
		if err := frame.Validate(); err != nil {
			return nil, fmt.Errorf("valid vector is receive-only, not canonical: %w", err)
		}
		return frame.MarshalBinary()
	case "tlv":
		fields, err := DecodeTLVs(wire, 0)
		if err != nil {
			return nil, err
		}
		return EncodeTLVs(fields)
	case "message":
		message := fuzzMessage(MessageType(*vector.MessageType))
		if message == nil {
			return nil, fmt.Errorf("unknown message type 0x%02x", *vector.MessageType)
		}
		if err := message.UnmarshalBinary(wire); err != nil {
			return nil, err
		}
		return message.(encoding.BinaryMarshaler).MarshalBinary()
	default:
		return nil, fmt.Errorf("unknown vector kind %q", vector.Kind)
	}
}

var vectorErrors = map[string]error{
	"ErrHeaderTooShort":      ErrHeaderTooShort,
	"ErrInvalidMagic":        ErrInvalidMagic,
	"ErrPaddingFlag":         ErrPaddingFlag,
	"ErrFrameLengthMismatch": ErrFrameLengthMismatch,
	"ErrTLVTooShort":         ErrTLVTooShort,
	"ErrTLVTruncated":        ErrTLVTruncated,
	"ErrInvalidPingResponse": ErrInvalidPingResponse,
	"ErrMessageLength":       ErrMessageLength,
	"ErrMessageReserved":     ErrMessageReserved,
	"ErrInvalidEpoch":        ErrInvalidEpoch,
	"ErrInvalidUTF8":         ErrInvalidUTF8,
}
