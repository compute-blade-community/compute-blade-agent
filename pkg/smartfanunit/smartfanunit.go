package smartfanunit

import (
	"github.com/compute-blade-community/compute-blade-agent/pkg/smartfanunit/proto"
)

const (
	BaudRate = 115200
)

func MatchCmd(cmd proto.Command) func(any) bool {
	return func(pktAny any) bool {
		pkt, ok := pktAny.(proto.Packet)
		if !ok {
			return false
		}
		if pkt.Command == cmd {
			return true
		}
		return false
	}
}
