package protocol

// Frame-write completeness (P1-10): a short write must never truncate a
// frame. Each test fails if WriteFrame issues single-shot writes.
import (
	"bytes"
	"testing"
)

// shortWriter yields at most one byte per Write call, modeling short
// writes that are legal on connections under backpressure.
type shortWriter struct {
	buf bytes.Buffer
}

func (s *shortWriter) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	return s.buf.Write(p[:1])
}

func TestWriteFrameSurvivesShortWrites(t *testing.T) {
	payload := bytes.Repeat([]byte("f"), 1000)
	sw := &shortWriter{}
	if err := WriteFrame(sw, FRequestData, payload); err != nil {
		t.Fatalf("WriteFrame: %v", err)
	}
	ft, got, err := ReadFrame(&sw.buf)
	if err != nil {
		t.Fatalf("ReadFrame: %v", err)
	}
	if ft != FRequestData || !bytes.Equal(got, payload) {
		t.Fatalf("round trip: type=%d bytes=%d, want %d + %d bytes", ft, len(got), FRequestData, len(payload))
	}
}

func TestWriteMetaFrameSurvivesShortWrites(t *testing.T) {
	payload := []byte(`{"type":"request_end"}`)
	sw := &shortWriter{}
	if err := WriteFrame(sw, FRequestEnd, payload); err != nil {
		t.Fatalf("WriteFrame: %v", err)
	}
	ft, got, err := ReadFrame(&sw.buf)
	if err != nil {
		t.Fatalf("ReadFrame: %v", err)
	}
	if ft != FRequestEnd || !bytes.Equal(got, payload) {
		t.Fatalf("round trip: type=%d body=%q", ft, got)
	}
}
