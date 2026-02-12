package tcap

import "fmt"

func UnmarshalAsn1ElementLength(b []byte) (int, error) {
	// Check the first byte of the length field
	if b[1] <= 0x7f {
		// Short Form: Length is exactly the value of the byte
		return int(b[1]), nil
	}

	// Long Form: Bits 7-1 tell us how many bytes follow
	numOctets := int(b[1] & 0x7f)

	if numOctets == 0 {
		return -1, fmt.Errorf("indefinite length not supported")
	}
	if len(b) < 2+numOctets {
		return -1, fmt.Errorf("buffer too short for long-form length")
	}

	// Accumulate the length from subsequent bytes
	var actualLength uint32
	for i := 0; i < numOctets; i++ {
		actualLength = (actualLength << 8) | uint32(b[2+i])
	}

	return int(actualLength), nil
}

// MarshalAsn1ElementLength encodes an integer length into ASN.1 BER format.
func MarshalAsn1ElementLength(length int) []byte {
	// 1. Short Form: bit 8 is 0. Length fits in 7 bits (0-127).
	if length <= 127 {
		return []byte{byte(length)}
	}

	// 2. Long Form: bit 8 of the first byte is 1.
	// The remaining 7 bits tell us how many subsequent bytes hold the length.
	var valBytes []byte
	tempLen := uint32(length)

	// Extract bytes from the length value (Big-Endian)
	for tempLen > 0 {
		valBytes = append([]byte{byte(tempLen & 0xff)}, valBytes...)
		tempLen >>= 8
	}

	// Create the header byte (0x80 | number of bytes)
	// Example: 0x81 if 1 byte follows, 0x82 if 2 bytes follow.
	header := 0x80 | byte(len(valBytes))

	return append([]byte{header}, valBytes...)
}
