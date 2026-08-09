package dgpserver

import (
	"errors"
	"testing"
	"time"

	"github.com/tr1xdev/datagram-server/pkg/dgpv1"
)

var fuzzHandler = HandlerFunc(func(*Context, any) error { return nil })

func FuzzConfigValidationBoundaries(f *testing.F) {
	seeds := [][7]uint8{
		{1, 1, 1, 1, 1, 1, 1}, // documented zero-value defaults
		{0, 0, 0, 0, 0, 0, 0}, // negative boundaries
		{2, 2, 2, 2, 2, 2, 2}, // smallest positive values
		{3, 3, 3, 3, 3, 3, 3}, // larger valid values
		{2, 3, 1, 2, 3, 1, 2},
	}
	for _, seed := range seeds {
		f.Add(seed[0], seed[1], seed[2], seed[3], seed[4], seed[5], seed[6])
	}

	durations := [...]time.Duration{-time.Nanosecond, 0, time.Nanosecond, 24 * time.Hour}
	counts := [...]int{-1, 0, 1, 1 << 12}

	f.Fuzz(func(t *testing.T, disconnectIndex, handshakeIndex, readIndex, queueIndex, handlerQueueIndex, handshakeLimitIndex, connectionLimitIndex uint8) {
		disconnect := durations[int(disconnectIndex)%len(durations)]
		dgp := dgpv1.ServerConfig{
			HandshakeTimeout:        durations[int(handshakeIndex)%len(durations)],
			ReadTimeout:             durations[int(readIndex)%len(durations)],
			OutboundQueue:           counts[int(queueIndex)%len(counts)],
			HandlerQueue:            counts[int(handlerQueueIndex)%len(counts)],
			MaxConcurrentHandshakes: counts[int(handshakeLimitIndex)%len(counts)],
			MaxActiveConnections:    counts[int(connectionLimitIndex)%len(counts)],
		}

		first, firstErr := New(Config{DGP: dgp, DisconnectTimeout: disconnect})
		second, secondErr := New(Config{DGP: dgp, DisconnectTimeout: disconnect})
		if errorClass(firstErr) != errorClass(secondErr) {
			t.Fatalf("New classification changed: %q then %q", errorClass(firstErr), errorClass(secondErr))
		}
		if (firstErr == nil) != (disconnect >= 0) {
			t.Fatalf("New(DisconnectTimeout=%v) error = %v", disconnect, firstErr)
		}
		if firstErr != nil {
			return
		}
		wantDisconnect := disconnect
		if wantDisconnect == 0 {
			wantDisconnect = 5 * time.Second
		}
		if first.config.DisconnectTimeout != wantDisconnect || second.config.DisconnectTimeout != wantDisconnect {
			t.Fatalf("DisconnectTimeout defaults = %v/%v, want %v", first.config.DisconnectTimeout, second.config.DisconnectTimeout, wantDisconnect)
		}
		if first.config.DGP.HandshakeTimeout != dgp.HandshakeTimeout || first.config.DGP.ReadTimeout != dgp.ReadTimeout ||
			first.config.DGP.OutboundQueue != dgp.OutboundQueue || first.config.DGP.HandlerQueue != dgp.HandlerQueue ||
			first.config.DGP.MaxConcurrentHandshakes != dgp.MaxConcurrentHandshakes || first.config.DGP.MaxActiveConnections != dgp.MaxActiveConnections {
			t.Fatalf("New changed delegated DGP boundaries: got %#v, want %#v", first.config.DGP, dgp)
		}
	})
}

func FuzzRouterRegistrationState(f *testing.F) {
	for _, seed := range [][4]uint8{{0, 0, 0, 0}, {1, 1, 1, 1}, {2, 2, 2, 2}, {1, 1, 0, 2}, {2, 0, 1, 1}} {
		f.Add(seed[0], seed[1], seed[2], seed[3])
	}

	f.Fuzz(func(t *testing.T, routeByte, formByte, duplicateByte, freezeByte uint8) {
		messageTypes := [...]dgpv1.MessageType{
			dgpv1.MessageTypeEncryptedData,
			dgpv1.MessageTypeAck,
			dgpv1.MessageTypeError,
			dgpv1.MessageTypePingPong,
		}
		messageType := messageTypes[int(routeByte)%len(messageTypes)]
		form := formByte % 3 // valid, nil interface, typed nil
		var handler Handler = fuzzHandler
		if form == 1 {
			handler = nil
		} else if form == 2 {
			var typedNil HandlerFunc
			handler = typedNil
		}

		var router Router
		if freezeByte%2 == 1 {
			if err := router.Freeze(); err != nil {
				t.Fatal(err)
			}
		}
		first := router.Handle(messageType, handler)
		second := first
		if duplicateByte%2 == 1 {
			second = router.Handle(messageType, fuzzHandler)
		}

		wantFirst := error(nil)
		switch {
		case messageType == dgpv1.MessageTypePingPong:
			wantFirst = ErrUnsupportedMessage
		case form != 0:
			wantFirst = ErrNilHandler
		case freezeByte%2 == 1:
			wantFirst = ErrServerStarted
		}
		assertErrorIs(t, "first registration", first, wantFirst)
		if duplicateByte%2 == 1 {
			wantSecond := error(nil)
			switch {
			case messageType == dgpv1.MessageTypePingPong:
				wantSecond = ErrUnsupportedMessage
			case freezeByte%2 == 1:
				wantSecond = ErrServerStarted
			case wantFirst == nil:
				wantSecond = ErrDuplicateHandler
			}
			assertErrorIs(t, "second registration", second, wantSecond)
		}
	})
}

func FuzzCommandRouterRegistrationState(f *testing.F) {
	for _, seed := range [][5]uint8{{0, 0, 0, 0, 0}, {1, 1, 1, 1, 1}, {2, 2, 2, 2, 2}, {7, 0, 1, 1, 0}, {255, 2, 1, 0, 1}} {
		f.Add(seed[0], seed[1], seed[2], seed[3], seed[4])
	}

	f.Fuzz(func(t *testing.T, commandByte, formByte, groupByte, duplicateByte, freezeByte uint8) {
		decoder := CommandDecoderFunc(func(message *dgpv1.EncryptedData) (Command, any, error) {
			return Command(message.AppMessageType), message, nil
		})
		router := NewCommandRouter(decoder)
		if freezeByte%2 == 1 {
			if err := router.dispatch(nil, &dgpv1.EncryptedData{AppMessageType: commandByte}); !errors.Is(err, ErrNotHandled) {
				t.Fatalf("freeze dispatch = %v", err)
			}
		}

		var handler Handler = fuzzHandler
		if formByte%3 == 1 {
			handler = nil
		} else if formByte%3 == 2 {
			var typedNil HandlerFunc
			handler = typedNil
		}
		register := func() error {
			if groupByte%2 == 0 {
				return router.Handle(Command(commandByte), handler)
			}
			return router.Group(func(group *CommandGroup) error {
				return group.Handle(Command(commandByte), handler)
			})
		}

		first := register()
		wantFirst := error(nil)
		if freezeByte%2 == 1 && groupByte%2 == 1 {
			wantFirst = ErrServerStarted
		} else if formByte%3 != 0 {
			wantFirst = ErrNilHandler
		} else if freezeByte%2 == 1 {
			wantFirst = ErrServerStarted
		}
		assertErrorIs(t, "first command registration", first, wantFirst)
		if duplicateByte%2 == 1 {
			second := register()
			wantSecond := wantFirst
			if wantFirst == nil {
				wantSecond = ErrDuplicateHandler
			}
			assertErrorIs(t, "second command registration", second, wantSecond)
		}
	})
}

func errorClass(err error) string {
	if err == nil {
		return "ok"
	}
	return err.Error()
}

func assertErrorIs(t *testing.T, operation string, got, want error) {
	t.Helper()
	if want == nil {
		if got != nil {
			t.Fatalf("%s = %v, want nil", operation, got)
		}
		return
	}
	if !errors.Is(got, want) {
		t.Fatalf("%s = %v, want %v", operation, got, want)
	}
}
