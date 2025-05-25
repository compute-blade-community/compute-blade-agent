package internal_agent

import (
	"github.com/sierrasoftworks/humane-errors-go"
)

type ListenMode string

const (
	ModeTcp  ListenMode = "tcp"
	ModeUnix ListenMode = "unix"
)

func ListenModeFromString(s string) (ListenMode, humane.Error) {
	switch s {
	case string(ModeTcp):
		return ModeTcp, nil
	case string(ModeUnix):
		return ModeUnix, nil
	default:
		return "", humane.New("invalid listen mode",
			"ensure you are passing a valid listen mode to the grpc server",
			"valid modes are: [tcp, unix]",
		)
	}
}

func (l ListenMode) String() string {
	return string(l)
}
