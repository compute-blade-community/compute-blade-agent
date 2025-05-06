package smartfanunit

import "github.com/uptime-industries/compute-blade-agent/pkg/smartfanunit/proto"

func float32To24Bit(val float32) proto.Data {
	// Convert float32 to number with 3 bytes (0.1 precision)
	tmp := uint32(val * 10)
	if tmp > 0xffffff {
		tmp = 0xffffff // cap
	}
	return proto.Data{
		uint8((tmp >> 16) & 0xFF),
		uint8((tmp >> 8) & 0xFF),
		uint8(tmp & 0xFF),
	}
}

func float32From24Bit(data proto.Data) float32 {
	tmp := uint32(data[0])<<16 | uint32(data[1])<<8 | uint32(data[2])
	return float32(tmp) / 10
}
