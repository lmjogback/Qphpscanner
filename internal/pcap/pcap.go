// Package pcap writes a libpcap-format capture that reconstructs the scanner's
// HTTP exchanges as TCP/IP conversations, giving an audit trail that opens in
// Wireshark/tcpdump. It is dependency-free and needs no privileges.
//
// The capture is synthesised from the application-layer exchanges the scanner
// performs (reconstructed HTTP/1.1 bytes with plausible TCP/IP framing), not a
// raw wire capture: for HTTPS the plaintext HTTP is recorded, and packet timing
// is approximate. It is intended as a faithful record of what was requested and
// returned, not a packet-timing forensic capture.
package pcap

import (
	"encoding/binary"
	"io"
	"sync"
	"time"
)

// Link type LINKTYPE_RAW: each packet starts at the IPv4 header.
const linkTypeRaw = 101

// Writer writes classic pcap records to an underlying writer.
type Writer struct {
	mu sync.Mutex
	w  io.Writer
}

// NewWriter writes the pcap global header and returns a Writer.
func NewWriter(w io.Writer) (*Writer, error) {
	hdr := make([]byte, 24)
	binary.LittleEndian.PutUint32(hdr[0:], 0xa1b2c3d4) // magic
	binary.LittleEndian.PutUint16(hdr[4:], 2)          // version major
	binary.LittleEndian.PutUint16(hdr[6:], 4)          // version minor
	binary.LittleEndian.PutUint32(hdr[16:], 262144)    // snaplen
	binary.LittleEndian.PutUint32(hdr[20:], linkTypeRaw)
	if _, err := w.Write(hdr); err != nil {
		return nil, err
	}
	return &Writer{w: w}, nil
}

// WritePacket writes one captured packet with a timestamp.
func (pw *Writer) WritePacket(ts time.Time, data []byte) error {
	pw.mu.Lock()
	defer pw.mu.Unlock()
	return pw.writePacketLocked(ts, data)
}

// writePacketLocked writes a record; the caller must hold pw.mu.
func (pw *Writer) writePacketLocked(ts time.Time, data []byte) error {
	rec := make([]byte, 16)
	binary.LittleEndian.PutUint32(rec[0:], uint32(ts.Unix()))
	binary.LittleEndian.PutUint32(rec[4:], uint32(ts.Nanosecond()/1000))
	binary.LittleEndian.PutUint32(rec[8:], uint32(len(data)))
	binary.LittleEndian.PutUint32(rec[12:], uint32(len(data)))
	if _, err := pw.w.Write(rec); err != nil {
		return err
	}
	_, err := pw.w.Write(data)
	return err
}

// maxSegment is the payload chunk size used when splitting a reconstructed
// HTTP message across TCP segments (a conventional Ethernet MSS).
const maxSegment = 1460

// HTTPFlow describes one reconstructed request/response pair to synthesise as a
// complete TCP conversation (handshake, data segments, teardown).
type HTTPFlow struct {
	Time       time.Time
	ClientIP   [4]byte
	ServerIP   [4]byte
	ClientPort uint16
	ServerPort uint16
	Request    []byte // reconstructed request bytes (may be empty)
	Response   []byte // reconstructed response bytes (empty if none arrived)
}

// WriteHTTPFlow synthesises a full TCP conversation for one HTTP exchange and
// writes every packet. The packets of a single flow are emitted contiguously so
// the capture stays readable even when concurrent flows share the writer.
func (pw *Writer) WriteHTTPFlow(f HTTPFlow) error {
	pw.mu.Lock()
	defer pw.mu.Unlock()

	const window = 64240
	cseq, sseq := uint32(1), uint32(1)
	emit := func(src, dst [4]byte, sp, dp uint16, seq, ack uint32, flags byte, payload []byte) error {
		return pw.writePacketLocked(f.Time, buildIPv4TCP(src, dst, sp, dp, seq, ack, flags, window, payload))
	}

	// Three-way handshake.
	if err := emit(f.ClientIP, f.ServerIP, f.ClientPort, f.ServerPort, cseq, 0, flagSYN, nil); err != nil {
		return err
	}
	cseq++
	if err := emit(f.ServerIP, f.ClientIP, f.ServerPort, f.ClientPort, sseq, cseq, flagSYN|flagACK, nil); err != nil {
		return err
	}
	sseq++
	if err := emit(f.ClientIP, f.ServerIP, f.ClientPort, f.ServerPort, cseq, sseq, flagACK, nil); err != nil {
		return err
	}

	// Request data, then the server ACKs it.
	var err error
	if cseq, err = pw.writeSegments(f.Time, f.ClientIP, f.ServerIP, f.ClientPort, f.ServerPort, cseq, sseq, window, f.Request); err != nil {
		return err
	}
	if len(f.Request) > 0 {
		if err = emit(f.ServerIP, f.ClientIP, f.ServerPort, f.ClientPort, sseq, cseq, flagACK, nil); err != nil {
			return err
		}
	}

	// Response data, then the client ACKs it.
	if sseq, err = pw.writeSegments(f.Time, f.ServerIP, f.ClientIP, f.ServerPort, f.ClientPort, sseq, cseq, window, f.Response); err != nil {
		return err
	}
	if len(f.Response) > 0 {
		if err = emit(f.ClientIP, f.ServerIP, f.ClientPort, f.ServerPort, cseq, sseq, flagACK, nil); err != nil {
			return err
		}
	}

	// Graceful teardown.
	if err = emit(f.ClientIP, f.ServerIP, f.ClientPort, f.ServerPort, cseq, sseq, flagFIN|flagACK, nil); err != nil {
		return err
	}
	cseq++
	if err = emit(f.ServerIP, f.ClientIP, f.ServerPort, f.ClientPort, sseq, cseq, flagFIN|flagACK, nil); err != nil {
		return err
	}
	sseq++
	return emit(f.ClientIP, f.ServerIP, f.ClientPort, f.ServerPort, cseq, sseq, flagACK, nil)
}

// writeSegments emits payload as one or more PSH/ACK data segments (chunked to
// maxSegment) and returns the advanced sequence number. The caller holds pw.mu.
func (pw *Writer) writeSegments(ts time.Time, src, dst [4]byte, sp, dp uint16, seq, ack uint32, window uint16, data []byte) (uint32, error) {
	for off := 0; off < len(data); off += maxSegment {
		end := off + maxSegment
		if end > len(data) {
			end = len(data)
		}
		chunk := data[off:end]
		flags := byte(flagACK)
		if end == len(data) {
			flags |= flagPSH
		}
		pkt := buildIPv4TCP(src, dst, sp, dp, seq, ack, flags, window, chunk)
		if err := pw.writePacketLocked(ts, pkt); err != nil {
			return seq, err
		}
		seq += uint32(len(chunk))
	}
	return seq, nil
}

// TCP flag bits.
const (
	flagFIN = 0x01
	flagSYN = 0x02
	flagRST = 0x04
	flagPSH = 0x08
	flagACK = 0x10
)

// buildIPv4TCP crafts a raw IPv4+TCP packet (no options) with valid checksums.
func buildIPv4TCP(src, dst [4]byte, sport, dport uint16, seq, ack uint32, flags byte, window uint16, payload []byte) []byte {
	tcp := make([]byte, 20+len(payload))
	binary.BigEndian.PutUint16(tcp[0:], sport)
	binary.BigEndian.PutUint16(tcp[2:], dport)
	binary.BigEndian.PutUint32(tcp[4:], seq)
	binary.BigEndian.PutUint32(tcp[8:], ack)
	tcp[12] = 5 << 4 // data offset = 5 words (20 bytes)
	tcp[13] = flags
	binary.BigEndian.PutUint16(tcp[14:], window)
	copy(tcp[20:], payload)

	total := 20 + len(tcp)
	ip := make([]byte, 20)
	ip[0] = 0x45 // version 4, IHL 5
	binary.BigEndian.PutUint16(ip[2:], uint16(total))
	binary.BigEndian.PutUint16(ip[6:], 0x4000) // don't fragment
	ip[8] = 64                                 // TTL
	ip[9] = 6                                  // protocol TCP
	copy(ip[12:16], src[:])
	copy(ip[16:20], dst[:])
	binary.BigEndian.PutUint16(ip[10:], checksum(ip))
	binary.BigEndian.PutUint16(tcp[16:], tcpChecksum(src, dst, tcp))

	return append(ip, tcp...)
}

// checksum is the 16-bit one's-complement sum used by IPv4/TCP.
func checksum(b []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(b); i += 2 {
		sum += uint32(b[i])<<8 | uint32(b[i+1])
	}
	if len(b)%2 == 1 {
		sum += uint32(b[len(b)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

func tcpChecksum(src, dst [4]byte, tcp []byte) uint16 {
	pseudo := make([]byte, 12+len(tcp))
	copy(pseudo[0:4], src[:])
	copy(pseudo[4:8], dst[:])
	pseudo[9] = 6 // protocol TCP
	binary.BigEndian.PutUint16(pseudo[10:], uint16(len(tcp)))
	copy(pseudo[12:], tcp)
	return checksum(pseudo)
}
