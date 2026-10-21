package php

import (
	"encoding/base64"
	"strconv"
	"strings"
)

// faviconHash computes the Shodan-compatible favicon fingerprint: MurmurHash3
// (32-bit, x86) of the MIME-base64 encoding of the icon bytes, rendered as a
// signed decimal. It matches Shodan's `http.favicon.hash`, so results can be
// pivoted on there.
func faviconHash(body []byte) string {
	b64 := mimeBase64(body)
	h := murmur3_32([]byte(b64), 0)
	return strconv.FormatInt(int64(int32(h)), 10)
}

// mimeBase64 mirrors Python's base64.encodebytes: standard base64 split into
// 76-character lines, each terminated by '\n' (including the final line).
func mimeBase64(data []byte) string {
	raw := base64.StdEncoding.EncodeToString(data)
	var b strings.Builder
	for i := 0; i < len(raw); i += 76 {
		end := i + 76
		if end > len(raw) {
			end = len(raw)
		}
		b.WriteString(raw[i:end])
		b.WriteByte('\n')
	}
	return b.String()
}

func murmur3_32(data []byte, seed uint32) uint32 {
	const (
		c1 = 0xcc9e2d51
		c2 = 0x1b873593
	)
	h := seed
	n := len(data) / 4
	for i := 0; i < n; i++ {
		k := uint32(data[i*4]) | uint32(data[i*4+1])<<8 | uint32(data[i*4+2])<<16 | uint32(data[i*4+3])<<24
		k *= c1
		k = (k << 15) | (k >> 17)
		k *= c2
		h ^= k
		h = (h << 13) | (h >> 19)
		h = h*5 + 0xe6546b64
	}
	var k uint32
	tail := data[n*4:]
	switch len(tail) {
	case 3:
		k ^= uint32(tail[2]) << 16
		fallthrough
	case 2:
		k ^= uint32(tail[1]) << 8
		fallthrough
	case 1:
		k ^= uint32(tail[0])
		k *= c1
		k = (k << 15) | (k >> 17)
		k *= c2
		h ^= k
	}
	h ^= uint32(len(data))
	h ^= h >> 16
	h *= 0x85ebca6b
	h ^= h >> 13
	h *= 0xc2b2ae35
	h ^= h >> 16
	return h
}
