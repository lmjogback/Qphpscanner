package pcap

import (
	"bytes"
	"encoding/binary"
	"strings"
	"testing"
	"time"
)

func TestNewWriterGlobalHeader(t *testing.T) {
	var buf bytes.Buffer
	if _, err := NewWriter(&buf); err != nil {
		t.Fatalf("NewWriter: %v", err)
	}
	b := buf.Bytes()
	if len(b) != 24 {
		t.Fatalf("global header = %d bytes, want 24", len(b))
	}
	if got := binary.LittleEndian.Uint32(b[0:]); got != 0xa1b2c3d4 {
		t.Errorf("magic = %#x, want 0xa1b2c3d4", got)
	}
	if maj, min := binary.LittleEndian.Uint16(b[4:]), binary.LittleEndian.Uint16(b[6:]); maj != 2 || min != 4 {
		t.Errorf("version = %d.%d, want 2.4", maj, min)
	}
	if got := binary.LittleEndian.Uint32(b[16:]); got != 262144 {
		t.Errorf("snaplen = %d, want 262144", got)
	}
	if got := binary.LittleEndian.Uint32(b[20:]); got != linkTypeRaw {
		t.Errorf("linktype = %d, want %d", got, linkTypeRaw)
	}
}

type failWriter struct{}

func (failWriter) Write([]byte) (int, error) { return 0, errBoom }

var errBoom = &boomErr{}

type boomErr struct{}

func (*boomErr) Error() string { return "boom" }

func TestNewWriterWriteError(t *testing.T) {
	if _, err := NewWriter(failWriter{}); err == nil {
		t.Fatal("expected error from failing writer")
	}
}

func TestWritePacket(t *testing.T) {
	var buf bytes.Buffer
	w, _ := NewWriter(&buf)
	ts := time.Unix(1_700_000_000, 123_000)
	if err := w.WritePacket(ts, []byte("abcd")); err != nil {
		t.Fatalf("WritePacket: %v", err)
	}
	rec := buf.Bytes()[24:]
	if got := binary.LittleEndian.Uint32(rec[0:]); got != 1_700_000_000 {
		t.Errorf("ts secs = %d", got)
	}
	if got := binary.LittleEndian.Uint32(rec[4:]); got != 123 {
		t.Errorf("ts usecs = %d, want 123", got)
	}
	if got := binary.LittleEndian.Uint32(rec[8:]); got != 4 {
		t.Errorf("caplen = %d, want 4", got)
	}
	if string(rec[16:]) != "abcd" {
		t.Errorf("payload = %q", rec[16:])
	}
}

// packet is a parsed raw-IPv4 record.
type packet struct {
	src, dst   [4]byte
	sport      uint16
	dport      uint16
	flags      byte
	payload    []byte
	ipOK, tcOK bool
}

func parseCapture(t *testing.T, data []byte) []packet {
	t.Helper()
	if len(data) < 24 {
		t.Fatalf("capture too short: %d bytes", len(data))
	}
	var out []packet
	off := 24
	for off+16 <= len(data) {
		capLen := int(binary.LittleEndian.Uint32(data[off+8:]))
		off += 16
		if off+capLen > len(data) {
			t.Fatalf("truncated packet at %d", off)
		}
		raw := data[off : off+capLen]
		off += capLen

		if raw[0]>>4 != 4 {
			t.Fatalf("not IPv4: version nibble %d", raw[0]>>4)
		}
		ihl := int(raw[0]&0x0f) * 4
		total := int(binary.BigEndian.Uint16(raw[2:]))
		if total > len(raw) {
			t.Fatalf("IP total length %d > captured %d", total, len(raw))
		}
		var p packet
		copy(p.src[:], raw[12:16])
		copy(p.dst[:], raw[16:20])
		p.ipOK = checksum(raw[:ihl]) == 0
		if raw[9] != 6 {
			t.Fatalf("protocol = %d, want 6 (TCP)", raw[9])
		}
		tcp := raw[ihl:total]
		p.sport = binary.BigEndian.Uint16(tcp[0:])
		p.dport = binary.BigEndian.Uint16(tcp[2:])
		p.flags = tcp[13]
		dataOff := int(tcp[12]>>4) * 4
		p.payload = tcp[dataOff:]
		p.tcOK = tcpChecksum(p.src, p.dst, tcp) == 0
		out = append(out, p)
	}
	return out
}

func TestWriteHTTPFlow(t *testing.T) {
	var buf bytes.Buffer
	w, _ := NewWriter(&buf)
	client := [4]byte{10, 0, 0, 1}
	server := [4]byte{203, 0, 113, 5}
	req := []byte("GET / HTTP/1.1\r\nHost: example.test\r\n\r\n")
	// Response body longer than one segment to exercise chunking.
	resp := []byte("HTTP/1.1 200 OK\r\nServer: Apache\r\n\r\n" + strings.Repeat("A", 3200))
	flow := HTTPFlow{
		Time: time.Unix(1_700_000_000, 0), ClientIP: client, ServerIP: server,
		ClientPort: 50000, ServerPort: 80, Request: req, Response: resp,
	}
	if err := w.WriteHTTPFlow(flow); err != nil {
		t.Fatalf("WriteHTTPFlow: %v", err)
	}

	pkts := parseCapture(t, buf.Bytes())
	if len(pkts) < 8 {
		t.Fatalf("got %d packets, want at least a full handshake+data+teardown", len(pkts))
	}

	var synSeen, synackSeen, finSeen bool
	var reqStream, respStream []byte
	respSegments := 0
	for _, p := range pkts {
		if !p.ipOK {
			t.Errorf("bad IP checksum on packet %+v", p)
		}
		if !p.tcOK {
			t.Errorf("bad TCP checksum on packet (flags %#x)", p.flags)
		}
		switch {
		case p.flags == flagSYN:
			synSeen = true
		case p.flags == flagSYN|flagACK:
			synackSeen = true
		case p.flags&flagFIN != 0:
			finSeen = true
		}
		if len(p.payload) == 0 {
			continue
		}
		if p.src == client {
			reqStream = append(reqStream, p.payload...)
		} else {
			respStream = append(respStream, p.payload...)
			respSegments++
		}
	}
	if !synSeen || !synackSeen || !finSeen {
		t.Errorf("handshake/teardown missing: syn=%v synack=%v fin=%v", synSeen, synackSeen, finSeen)
	}
	if !bytes.Equal(reqStream, req) {
		t.Errorf("reassembled request mismatch:\n got %q\nwant %q", reqStream, req)
	}
	if !bytes.Equal(respStream, resp) {
		t.Errorf("reassembled response mismatch (%d vs %d bytes)", len(respStream), len(resp))
	}
	if respSegments < 3 {
		t.Errorf("response should be chunked into >=3 segments, got %d", respSegments)
	}
}

func TestWriteHTTPFlowNoResponse(t *testing.T) {
	var buf bytes.Buffer
	w, _ := NewWriter(&buf)
	flow := HTTPFlow{
		Time: time.Now(), ClientIP: [4]byte{10, 0, 0, 1}, ServerIP: [4]byte{10, 0, 0, 2},
		ClientPort: 40000, ServerPort: 443, Request: []byte("GET / HTTP/1.1\r\n\r\n"),
		// Response nil: connection-level failure.
	}
	if err := w.WriteHTTPFlow(flow); err != nil {
		t.Fatalf("WriteHTTPFlow: %v", err)
	}
	pkts := parseCapture(t, buf.Bytes())
	for _, p := range pkts {
		if p.src == flow.ServerIP && len(p.payload) > 0 {
			t.Errorf("unexpected server payload when no response")
		}
	}
}

func TestWriteSegmentsBoundary(t *testing.T) {
	var buf bytes.Buffer
	w, _ := NewWriter(&buf)
	// Exactly two full segments.
	data := bytes.Repeat([]byte("x"), maxSegment*2)
	seq, err := w.writeSegments(time.Now(), [4]byte{10, 0, 0, 1}, [4]byte{10, 0, 0, 2}, 1, 2, 100, 200, 10, data)
	if err != nil {
		t.Fatalf("writeSegments: %v", err)
	}
	if seq != 100+uint32(len(data)) {
		t.Errorf("seq advanced to %d, want %d", seq, 100+uint32(len(data)))
	}
	pkts := parseCapture(t, buf.Bytes())
	if len(pkts) != 2 {
		t.Fatalf("got %d segments, want 2", len(pkts))
	}
	if pkts[0].flags&flagPSH != 0 {
		t.Errorf("first full segment should not carry PSH")
	}
	if pkts[1].flags&flagPSH == 0 {
		t.Errorf("last segment should carry PSH")
	}
}

func TestChecksumOddLength(t *testing.T) {
	// A one-byte buffer exercises the odd-length tail path.
	if checksum([]byte{0xff}) == 0 {
		t.Error("checksum of {0xff} should be non-zero")
	}
	// Property: summing a buffer plus its checksum folds to zero.
	hdr := []byte{0x45, 0, 0, 20, 0, 0, 0x40, 0, 64, 6, 0, 0, 10, 0, 0, 1, 10, 0, 0, 2}
	binary.BigEndian.PutUint16(hdr[10:], checksum(hdr))
	if checksum(hdr) != 0 {
		t.Error("checksum over header including its checksum should be 0")
	}
}
