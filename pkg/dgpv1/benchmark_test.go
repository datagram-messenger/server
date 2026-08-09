package dgpv1

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/crypto/chacha20poly1305"
)

var benchmarkSink []byte

type messengerMessage struct {
	MessageID   string `json:"message_id"`
	SenderID    string `json:"sender_id"`
	RecipientID string `json:"recipient_id"`
	Timestamp   int64  `json:"timestamp"`
	Text        string `json:"text"`
}

// BenchmarkMessengerWireFormats compares secure in-memory envelopes around
// identical pre-serialized JSON. The HTTP case is synthetic, not ordinary HTTP
// or TLS: it adds the same ChaCha20-Poly1305 work used by DGPv1.
func BenchmarkMessengerWireFormats(b *testing.B) {
	for _, textSize := range []int{64, 1024, 16384} {
		payload, err := json.Marshal(messengerMessage{
			MessageID: "msg-01JAZ6Y9M4E7X2C8KQ5V3N1T0R", SenderID: "user-alice",
			RecipientID: "user-bob", Timestamp: 1735689600000, Text: strings.Repeat("x", textSize),
		})
		if err != nil {
			b.Fatal(err)
		}
		b.Run(fmt.Sprintf("%dB-text", textSize), func(b *testing.B) {
			benchmarkDGPv1Secure(b, payload)
			benchmarkHTTP1SyntheticSecure(b, payload)
		})
	}
}

func benchmarkDGPv1Secure(b *testing.B, payload []byte) {
	codec, err := NewCodec(CipherChaCha20Poly1305, make([]byte, KeySize))
	if err != nil {
		b.Fatal(err)
	}
	sessionID := [16]byte{1}
	frame, err := codec.Encrypt(MessageTypeEncryptedData, sessionID, 1, payload, 0)
	if err != nil {
		b.Fatal(err)
	}
	wire, err := frame.MarshalBinary()
	if err != nil {
		b.Fatal(err)
	}
	assertDGPDecode(b, codec, wire, payload)

	b.Run("DGPv1-secure-envelope/encode", func(b *testing.B) {
		b.ReportAllocs()
		b.SetBytes(int64(len(payload)))
		for i := 0; i < b.N; i++ {
			frame, err := codec.Encrypt(MessageTypeEncryptedData, sessionID, uint64(i+1), payload, 0)
			if err != nil {
				b.Fatal(err)
			}
			benchmarkSink, err = frame.MarshalBinary()
			if err != nil {
				b.Fatal(err)
			}
		}
		reportWireMetrics(b, len(wire), len(payload))
	})
	b.Run("DGPv1-secure-envelope/decode", func(b *testing.B) {
		b.ReportAllocs()
		b.SetBytes(int64(len(payload)))
		for i := 0; i < b.N; i++ {
			var decoded Frame
			if err := decoded.UnmarshalBinary(wire); err != nil {
				b.Fatal(err)
			}
			benchmarkSink, err = codec.Decrypt(decoded)
			if err != nil {
				b.Fatal(err)
			}
		}
		reportWireMetrics(b, len(wire), len(payload))
	})
}

func benchmarkHTTP1SyntheticSecure(b *testing.B, payload []byte) {
	aead, err := chacha20poly1305.New(make([]byte, chacha20poly1305.KeySize))
	if err != nil {
		b.Fatal(err)
	}
	header := httpRequestHeader(len(payload) + aead.Overhead())
	var nonce [chacha20poly1305.NonceSize]byte
	binary.LittleEndian.PutUint64(nonce[4:], 1)
	wire := aead.Seal(append([]byte(nil), header...), nonce[:], payload, header)
	assertHTTPDecode(b, aead, nonce[:], wire, payload)

	b.Run("HTTP1-synthetic-secure-envelope/encode", func(b *testing.B) {
		b.ReportAllocs()
		b.SetBytes(int64(len(payload)))
		for i := 0; i < b.N; i++ {
			header := httpRequestHeader(len(payload) + aead.Overhead())
			var n [chacha20poly1305.NonceSize]byte
			binary.LittleEndian.PutUint64(n[4:], uint64(i+1))
			benchmarkSink = aead.Seal(header, n[:], payload, header)
		}
		reportWireMetrics(b, len(wire), len(payload))
	})
	b.Run("HTTP1-synthetic-secure-envelope/decode", func(b *testing.B) {
		b.ReportAllocs()
		b.SetBytes(int64(len(payload)))
		for i := 0; i < b.N; i++ {
			head, body, err := parseHTTPRequest(wire)
			if err != nil {
				b.Fatal(err)
			}
			benchmarkSink, err = aead.Open(nil, nonce[:], body, head)
			if err != nil {
				b.Fatal(err)
			}
		}
		reportWireMetrics(b, len(wire), len(payload))
	})
}

func httpRequestHeader(contentLength int) []byte {
	return []byte("POST /v1/messages HTTP/1.1\r\nHost: messenger.example\r\nContent-Type: application/octet-stream\r\nContent-Encoding: benchmark-chacha20poly1305\r\nContent-Length: " + strconv.Itoa(contentLength) + "\r\n\r\n")
}

func parseHTTPRequest(wire []byte) ([]byte, []byte, error) {
	end := bytes.Index(wire, []byte("\r\n\r\n"))
	if end < 0 {
		return nil, nil, errors.New("missing HTTP header terminator")
	}
	head := wire[:end+4]
	lines := bytes.Split(wire[:end], []byte("\r\n"))
	if len(lines) < 2 || !bytes.Equal(lines[0], []byte("POST /v1/messages HTTP/1.1")) {
		return nil, nil, errors.New("invalid HTTP request line")
	}
	contentLength := -1
	host, contentType, contentEncoding := false, false, false
	for _, line := range lines[1:] {
		name, value, ok := bytes.Cut(line, []byte(":"))
		if !ok {
			return nil, nil, errors.New("malformed HTTP header")
		}
		value = bytes.TrimSpace(value)
		switch strings.ToLower(string(name)) {
		case "host":
			host = len(value) > 0
		case "content-type":
			contentType = bytes.Equal(value, []byte("application/octet-stream"))
		case "content-encoding":
			contentEncoding = bytes.Equal(value, []byte("benchmark-chacha20poly1305"))
		case "content-length":
			var err error
			contentLength, err = strconv.Atoi(string(value))
			if err != nil {
				return nil, nil, errors.New("invalid Content-Length")
			}
		}
	}
	body := wire[end+4:]
	if !host || !contentType || !contentEncoding || contentLength != len(body) {
		return nil, nil, errors.New("incomplete or inconsistent HTTP envelope")
	}
	return head, body, nil
}

func assertDGPDecode(b *testing.B, codec *Codec, wire, want []byte) {
	b.Helper()
	var frame Frame
	if err := frame.UnmarshalBinary(wire); err != nil {
		b.Fatal(err)
	}
	got, err := codec.Decrypt(frame)
	if err != nil || !bytes.Equal(got, want) {
		b.Fatalf("DGPv1 correctness check failed: %v", err)
	}
}

func assertHTTPDecode(b *testing.B, aead interface {
	Open([]byte, []byte, []byte, []byte) ([]byte, error)
}, nonce, wire, want []byte) {
	b.Helper()
	head, body, err := parseHTTPRequest(wire)
	if err != nil {
		b.Fatal(err)
	}
	got, err := aead.Open(nil, nonce, body, head)
	if err != nil || !bytes.Equal(got, want) {
		b.Fatalf("HTTP correctness check failed: %v", err)
	}
}

func reportWireMetrics(b *testing.B, wireBytes, payloadBytes int) {
	b.ReportMetric(float64(wireBytes), "wire-B/op")
	b.ReportMetric(float64(wireBytes-payloadBytes), "overhead-B/op")
}

func BenchmarkSyntheticWireCodecs(b *testing.B) {
	for _, size := range []int{64, 1024, 16384} {
		payload := make([]byte, size)
		for i := range payload {
			payload[i] = byte(i)
		}
		b.Run(fmt.Sprintf("DGPv1FrameAEAD/%dB/encode", size), func(b *testing.B) {
			codec, _ := NewCodec(CipherChaCha20Poly1305, make([]byte, KeySize))
			b.ReportAllocs()
			b.SetBytes(int64(size))
			for i := 0; i < b.N; i++ {
				frame, err := codec.Encrypt(MessageTypeEncryptedData, [16]byte{1}, uint64(i+1), payload, 0)
				if err != nil {
					b.Fatal(err)
				}
				benchmarkSink, err = frame.MarshalBinary()
				if err != nil {
					b.Fatal(err)
				}
			}
		})
		b.Run(fmt.Sprintf("DGPv1FrameAEAD/%dB/decode", size), func(b *testing.B) {
			codec, _ := NewCodec(CipherChaCha20Poly1305, make([]byte, KeySize))
			frame, _ := codec.Encrypt(MessageTypeEncryptedData, [16]byte{1}, 1, payload, 0)
			wire, _ := frame.MarshalBinary()
			b.ReportAllocs()
			b.SetBytes(int64(size))
			for i := 0; i < b.N; i++ {
				var decoded Frame
				if err := decoded.UnmarshalBinary(wire); err != nil {
					b.Fatal(err)
				}
				var err error
				benchmarkSink, err = codec.Decrypt(decoded)
				if err != nil {
					b.Fatal(err)
				}
			}
		})
		for _, baseline := range []struct {
			name   string
			header int
		}{
			{"LengthPrefixedAEAD", 4},
			{"WebSocketLikeBinaryAEAD", websocketHeaderSize(size + chacha20poly1305.Overhead)},
		} {
			baseline := baseline
			b.Run(fmt.Sprintf("%s/%dB/encode", baseline.name, size), func(b *testing.B) {
				aead, _ := chacha20poly1305.New(make([]byte, chacha20poly1305.KeySize))
				header := make([]byte, baseline.header)
				writeSyntheticLength(header, size+aead.Overhead())
				b.ReportAllocs()
				b.SetBytes(int64(size))
				for i := 0; i < b.N; i++ {
					n := make([]byte, aead.NonceSize())
					binary.LittleEndian.PutUint64(n[4:], uint64(i+1))
					wire := append([]byte(nil), header...)
					benchmarkSink = aead.Seal(wire, n, payload, header)
				}
			})
			b.Run(fmt.Sprintf("%s/%dB/decode", baseline.name, size), func(b *testing.B) {
				aead, _ := chacha20poly1305.New(make([]byte, chacha20poly1305.KeySize))
				header := make([]byte, baseline.header)
				writeSyntheticLength(header, size+aead.Overhead())
				n := make([]byte, aead.NonceSize())
				binary.LittleEndian.PutUint64(n[4:], 1)
				wire := aead.Seal(append([]byte(nil), header...), n, payload, header)
				b.ReportAllocs()
				b.SetBytes(int64(size))
				for i := 0; i < b.N; i++ {
					var err error
					benchmarkSink, err = aead.Open(nil, n, wire[len(header):], wire[:len(header)])
					if err != nil {
						b.Fatal(err)
					}
				}
			})
		}
	}
}

func websocketHeaderSize(payload int) int {
	if payload <= 125 {
		return 2
	}
	return 4
}
func writeSyntheticLength(header []byte, length int) {
	if len(header) == 2 {
		header[0] = 0x82
		header[1] = byte(length)
		return
	}
	binary.BigEndian.PutUint32(header[len(header)-4:], uint32(length))
	if len(header) == 4 && header[0] == 0 {
		header[0] = 0x82
		header[1] = 126
	}
}
