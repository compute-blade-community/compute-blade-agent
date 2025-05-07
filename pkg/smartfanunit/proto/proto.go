package proto

import (
	"context"
	"errors"
	"io"
	"time"

	"tinygo.org/x/drivers"
)

// Simple P2P protocol for communicating over a serial port.
// All commands are 4 bytes long, the first byte is the command, the remaining bytes are data
// This allows encoding of 256 commands, with a payload of 3 bytes each.
// Includes SOF/EOF framing and a checksum. Colliding bytes in the payload are escaped.

var (
	ErrChecksumMismatch   = errors.New("checksum mismatch")
	ErrInvalidFramingByte = errors.New("invalid framing byte")
)

const (
	SOF = 0x7E // Start of Frame
	ESC = 0x7D // Escape character
	XOR = 0x20 // XOR value for escaping
	EOF = 0x7F // End of Frame
)

// Command represents the command byte.
type Command uint8

// Data represents the three data bytes.
type Data [3]uint8

// Packet represents a serial packet with command and data.
type Packet struct {
	Command Command
	Data    Data
}

// Checksum calculates the Checksum for a packet.
func (packet *Packet) Checksum() uint8 {
	crc := uint8(0)
	crc ^= uint8(packet.Command)
	for _, d := range packet.Data {
		crc ^= d
	}
	return crc
}

// WritePacket writes a packet to an io.Writer with escaping.
func WritePacket(_ context.Context, w io.Writer, packet Packet) error {
	checksum := packet.Checksum()

	buf := []uint8{uint8(packet.Command), packet.Data[0], packet.Data[1], packet.Data[2], checksum}

	_, err := w.Write([]uint8{SOF})
	if err != nil {
		return err
	}
	for _, b := range buf {
		if b == SOF || b == EOF || b == ESC {
			_, err := w.Write([]uint8{ESC, b ^ XOR})
			if err != nil {
				return err
			}
		} else {
			_, err := w.Write([]uint8{b})
			if err != nil {
				return err
			}
		}
	}
	_, err = w.Write([]uint8{EOF})
	return err
}

// ReadPacket reads a packet from an io.Reader with escaping.
// This is blocking and drops invalid bytes until a valid packet is received.
func ReadPacket(ctx context.Context, r io.Reader) (Packet, error) {
	var buffer []uint8

	started := false
	escaped := false

	uart, isUart := r.(drivers.UART)

	for {

		// Check if context is done before reading
		select {
		case <-ctx.Done():
			return Packet{}, ctx.Err()
		default:
		}

		if isUart && uart.Buffered() == 0 {
			// Allows TinyGo to switch to other goroutines
			time.Sleep(time.Millisecond)
			continue
		}

		b := make([]uint8, 1)
		_, err := r.Read(b)
		if err != nil {
			return Packet{}, err
		}

		if b[0] == SOF && !started {
			started = true
		} else if !started {
			continue
		}

		if escaped {
			buffer = append(buffer, b[0]^XOR)
			escaped = false
		} else if b[0] == ESC {
			escaped = true
		} else {
			buffer = append(buffer, b[0])
		}

		if b[0] == EOF && !escaped {
			if len(buffer) == 7 { // Packet size
				break
			} else {
				buffer = []uint8{}
			}
		}
	}

	if buffer[0] != SOF || buffer[len(buffer)-1] != EOF {
		return Packet{}, ErrInvalidFramingByte
	}

	command := Command(buffer[1])
	data := Data{buffer[2], buffer[3], buffer[4]}
	checksum := buffer[5]
	pkt := Packet{command, data}
	expectedChecksum := pkt.Checksum()

	if checksum != expectedChecksum {
		return Packet{}, ErrChecksumMismatch
	}

	return pkt, nil
}
