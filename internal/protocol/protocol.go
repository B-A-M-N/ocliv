// Package protocol defines Ocliv's versioned length-prefixed stream framing.
//
// Every yamux stream carries exactly one proxied request/response exchange.
// Frames: 1-byte type + 4-byte big-endian length + payload.
// Metadata frames (JSON) are capped at 32 KiB; data chunks at 64 KiB.
// Lengths are validated BEFORE allocation (E03). Unknown mandatory types
// are rejected; additive negotiation must precede any new type.
package protocol

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"

	"ocliv/internal/apperr"
)

// Version negotiation.
const (
	Version      = "ocliv/1"
	MinVersion   = "ocliv/1"
	MaxVersion   = "ocliv/1"
	MetaCap      = 32 * 1024
	DataCap      = 64 * 1024
	MaxBodyBytes = 64 << 20 // 64 MiB fixed build-time cap, enforced as a running total
)

// Frame types.
const (
	FRequestHead   = 0x01
	FRequestData   = 0x02
	FRequestEnd    = 0x03
	FResponseHead  = 0x04
	FResponseData  = 0x05
	FResponseEnd   = 0x06
	FAbort         = 0x07
	FUpgradeAccept = 0x08
	FUpgradeBytes  = 0x09
	FClose         = 0x0A
)

// RequestHead is sent relay -> agent before any stream data (C01: auth and
// route validation happen before this frame is ever written).
type RequestHead struct {
	Type       string            `json:"type"` // "request_head"
	Proto      string            `json:"proto"`
	RequestID  string            `json:"request_id"`
	LeaseID    string            `json:"lease_id"`
	Generation uint64            `json:"generation"`
	Method     string            `json:"method"`
	Path       string            `json:"path"`
	RawQuery   string            `json:"raw_query"`
	Headers    map[string]string `json:"headers"`
	RemoteIP   string            `json:"remote_ip"`
	PubOrigin  string            `json:"pub_origin"`
	BodyKnown  bool              `json:"body_known"`
	BodyLen    int64             `json:"body_len"`
	UpgradeWS  bool              `json:"upgrade_ws"`
}

// ResponseHead is sent agent -> relay.
type ResponseHead struct {
	Type        string            `json:"type"` // "response_head"
	Proto       string            `json:"proto"`
	RequestID   string            `json:"request_id"`
	Status      int               `json:"status"`
	Headers     map[string]string `json:"headers"`
	BodyKnown   bool              `json:"body_known"`
	BodyLen     int64             `json:"body_len"`
	UpgradeOK   bool              `json:"upgrade_ok"`
	AcceptValue string            `json:"accept_value,omitempty"`
}

// Abort carries a typed cancellation reason both directions (E06).
type Abort struct {
	Type   string `json:"type"` // "abort"
	Code   string `json:"code"`
	Reason string `json:"reason"`
}

// EndFrame terminates a body stream carrying trailers (correct trailer
// semantics) or empty trailers when the application sent none.
type EndFrame struct {
	Type     string            `json:"type"` // "request_end" | "response_end"
	Trailers map[string]string `json:"trailers,omitempty"`
}

// UpgradeAccept confirms the local 101 with its accept value.
type UpgradeAccept struct {
	Type    string            `json:"type"` // "upgrade_accept"
	Accept  string            `json:"accept"`
	Headers map[string]string `json:"headers,omitempty"` // e.g. subprotocol
}

// WriteFrame validates length before allocation and writes one frame.
func WriteFrame(w io.Writer, ftype byte, payload []byte) error {
	cap := DataCap
	if isMeta(ftype) {
		cap = MetaCap
	}
	if len(payload) > cap {
		return apperr.E(apperr.CodeSizeLimit,
			fmt.Sprintf("frame type 0x%02x payload %d exceeds cap %d", ftype, len(payload), cap), nil)
	}
	var hdr [5]byte
	hdr[0] = ftype
	binary.BigEndian.PutUint32(hdr[1:], uint32(len(payload)))
	// Connections may short-write under backpressure: loop until the
	// whole frame is out, or the first hard error (P1-10).
	if err := WriteFull(w, hdr[:]); err != nil {
		return err
	}
	if len(payload) > 0 {
		if err := WriteFull(w, payload); err != nil {
			return err
		}
	}
	return nil
}

// WriteFull writes all of p to w, retrying short writes. Connections
// may short-write under backpressure; a single Write is not enough.
func WriteFull(w io.Writer, p []byte) error {
	for len(p) > 0 {
		n, err := w.Write(p)
		if err != nil {
			return err
		}
		// A Writer must return a non-zero n or a non-nil err, but
		// defend anyway: no progress without an error is a stuck
		// writer, not a complete one.
		if n <= 0 {
			return io.ErrShortWrite
		}
		p = p[n:]
	}
	return nil
}

// ReadFrame validates the declared length before allocating (E03).
func ReadFrame(r io.Reader) (byte, []byte, error) {
	var hdr [5]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return 0, nil, err
	}
	ftype := hdr[0]
	if !knownType(ftype) {
		return 0, nil, apperr.E(apperr.CodeProtocol,
			fmt.Sprintf("unknown frame type 0x%02x rejected", ftype), nil)
	}
	n := binary.BigEndian.Uint32(hdr[1:])
	cap := uint32(DataCap)
	if isMeta(ftype) {
		cap = MetaCap
	}
	if n > cap {
		return 0, nil, apperr.E(apperr.CodeSizeLimit,
			fmt.Sprintf("frame type 0x%02x declares %d bytes, cap %d: rejected before allocation", ftype, n, cap), nil)
	}
	payload := make([]byte, n)
	if _, err := io.ReadFull(r, payload); err != nil {
		return 0, nil, err
	}
	return ftype, payload, nil
}

func isMeta(ftype byte) bool {
	switch ftype {
	case FRequestHead, FResponseHead, FAbort, FUpgradeAccept, FClose:
		return true
	}
	return false
}

func knownType(ftype byte) bool {
	switch ftype {
	case FRequestHead, FRequestData, FRequestEnd,
		FResponseHead, FResponseData, FResponseEnd,
		FAbort, FUpgradeAccept, FUpgradeBytes, FClose:
		return true
	}
	return false
}

// MarshalJSON is a helper that enforces the metadata cap.
func MarshalJSON(v any) ([]byte, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	if len(raw) > MetaCap {
		return nil, apperr.E(apperr.CodeSizeLimit, "metadata frame exceeds 32 KiB", nil)
	}
	return raw, nil
}
