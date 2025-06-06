package proto_test

import (
	"bytes"
	"context"
	"testing"

	"github.com/compute-blade-community/compute-blade-agent/pkg/smartfanunit/proto"
	"github.com/stretchr/testify/assert"
)

func TestWritePacket(t *testing.T) {
	t.Parallel()

	testcases := []struct {
		name     string
		packet   proto.Packet
		expected []uint8
	}{
		{
			name: "Simple packet",
			packet: proto.Packet{
				Command: proto.Command(0x01),
				Data:    proto.Data{0x11, 0x12, 0x13},
			},
			expected: []uint8{proto.SOF, 0x01, 0x11, 0x12, 0x13, 0x11, proto.EOF},
		},
		{
			name: "ESC in payload and checksum == ESC",
			packet: proto.Packet{
				Command: proto.Command(0x01),
				Data:    proto.Data{proto.ESC, 0x12, 0x13},
				// Checksup: 0x7d -> proto.ESC as well
			},
			expected: []uint8{
				// Start of frame
				proto.SOF,
				0x01,
				// Escaped data
				proto.ESC,
				proto.XOR ^ proto.ESC,
				// continuing non-escaped data
				0x12, 0x13,
				// escape checksum
				proto.ESC,
				proto.XOR ^ proto.ESC,
				// end of frame
				proto.EOF,
			},
		},
		{
			name: "EOF, SOF and ESC in payload",
			packet: proto.Packet{
				// 0x01, 0x7e, 0x7f, 0x7d
				Command: proto.Command(0xff),
				Data:    proto.Data{proto.SOF, proto.EOF, proto.ESC},
				// Checksup: 0x7d -> proto.ESC as well
			},
			expected: []uint8{
				// Start of frame
				proto.SOF,
				0xff,
				// Escaped SOF
				proto.ESC,
				proto.XOR ^ proto.SOF,
				// Escaped EOF
				proto.ESC,
				proto.XOR ^ proto.EOF,
				// Escaped ESC
				proto.ESC,
				proto.XOR ^ proto.ESC,
				// Checksum
				0x83,
				// end of frame
				proto.EOF,
			},
		},
	}

	for _, tcl := range testcases {
		tc := tcl
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var buffer bytes.Buffer
			err := proto.WritePacket(context.TODO(), &buffer, tc.packet)
			assert.NoError(t, err)
			assert.Equal(t, tc.expected, buffer.Bytes())
		})
	}
}

func FuzzPacketReadWrite(f *testing.F) {
	f.Add(uint8(0x01), uint8(0x02), uint8(0x03), uint8(0x04))

	// Fuzz function
	f.Fuzz(func(t *testing.T, cmd, d0, d1, d2 uint8) {
		pkt := proto.Packet{
			Command: proto.Command(cmd),
			Data:    proto.Data([]uint8{d0, d1, d2}),
		}

		var buffer bytes.Buffer
		err := proto.WritePacket(context.TODO(), &buffer, pkt)
		assert.NoError(t, err)

		readPkt, err := proto.ReadPacket(context.TODO(), &buffer)
		assert.NoError(t, err)
		assert.Equal(t, pkt, readPkt)
	})
}

func TestPacketReadWrite(t *testing.T) {
	testcases := []struct {
		name   string
		packet proto.Packet
	}{
		{
			name: "Simple packet",
			packet: proto.Packet{
				Command: proto.Command(0x01),
				Data:    proto.Data{0x11, 0x12, 0x13},
			},
		},
		{
			name: "EOF, SOF and ESC in payload",
			packet: proto.Packet{
				Command: proto.Command(0xff),
				Data:    proto.Data{proto.SOF, proto.EOF, proto.ESC},
			},
		},
	}

	for _, tcl := range testcases {
		tc := tcl
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var buffer bytes.Buffer
			err := proto.WritePacket(context.TODO(), &buffer, tc.packet)
			assert.NoError(t, err)

			packet, err := proto.ReadPacket(context.TODO(), &buffer)
			assert.NoError(t, err)
			assert.Equal(t, tc.packet, packet)
		})
	}
}

func TestReadPacketChecksumError(t *testing.T) {
	// Create a simple packet with an invalid Checksum
	var buffer bytes.Buffer
	invalidPacket := []uint8{
		proto.SOF,
		0x01,
		0x11,
		0x22,
		0x33,
		0x00,
		proto.EOF,
	} // 0x00 as checksum is invalid here

	// Write invalid packet to buffer
	for _, b := range invalidPacket {
		_, err := buffer.Write([]uint8{b})
		if err != nil {
			t.Fatalf("Failed to write to buffer: %v", err)
		}
	}

	// Attempt to read the packet with a Checksum error
	_, err := proto.ReadPacket(context.TODO(), &buffer)
	assert.ErrorIs(t, err, proto.ErrChecksumMismatch)
}

func TestReadPacketDirtyReader(t *testing.T) {
	// Create a simple packet with an invalid Checksum
	var buffer bytes.Buffer
	invalidPacket := []uint8{
		// Incomplete previous packet
		0x01,
		0x12,
		0x13,
		0x11,
		proto.EOF,
		// Actual packet
		proto.SOF,
		0x01,
		0x11,
		0x12,
		0x13,
		0x11,
		proto.EOF,
	}

	// Write invalid packet to buffer
	for _, b := range invalidPacket {
		_, err := buffer.Write([]uint8{b})
		if err != nil {
			t.Fatalf("Failed to write to buffer: %v", err)
		}
	}

	// Attempt to read the packet with a Checksum error
	pkt, err := proto.ReadPacket(context.TODO(), &buffer)
	assert.NoError(t, err)
	assert.Equal(t, proto.Packet{Command: proto.Command(0x01), Data: proto.Data{0x11, 0x12, 0x13}}, pkt)
}
