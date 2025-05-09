//go:build !tinygo

package hal

import (
	"context"
	"errors"
	"io"
	"sync"

	"github.com/uptime-industries/compute-blade-agent/pkg/events"
	"github.com/uptime-industries/compute-blade-agent/pkg/hal/led"
	"github.com/uptime-industries/compute-blade-agent/pkg/log"
	"github.com/uptime-industries/compute-blade-agent/pkg/smartfanunit"
	"github.com/uptime-industries/compute-blade-agent/pkg/smartfanunit/proto"
	"go.bug.st/serial"
	"golang.org/x/sync/errgroup"
)

func SmartFanUnitPresent(ctx context.Context, portName string) (bool, error) {
	// Open the serial port.
	log.FromContext(ctx).Info("Opening serial port")

	rwc, err := serial.Open(portName, &serial.Mode{
		BaudRate: smartfanunit.BaudRate,
	})
	if err != nil {
		return false, err
	}
	log.FromContext(ctx).Info("Opened serial port")
	defer func(rwc serial.Port) {
		err := rwc.Close()
		if err != nil {
			log.FromContext(ctx).WithError(err).Warn("Error while closing serial port")
		}
	}(rwc)

	// Close reader after context is done
	go func() {
		<-ctx.Done()
		log.FromContext(ctx).Warn("Closing serial port")
		err := rwc.Close()
		if err != nil {
			log.FromContext(ctx).WithError(err).Warn("Error while closing serial port")
		}
	}()

	// read byte after byte, matching it to the SOF header used by the smart fan unit protocol.
	// -> if that's present, we have a smart fanunit connected.
	for {
		b := make([]byte, 1)
		log.FromContext(ctx).Info("Waiting for next byte from serial port")
		_, err := rwc.Read(b)
		if err != nil {
			return false, err
		}
		if b[0] == proto.SOF {
			return true, nil
		}
	}
}

func NewSmartFanUnit(portName string) (FanUnit, error) {
	// Open the serial port.
	rwc, err := serial.Open(portName, &serial.Mode{
		BaudRate: smartfanunit.BaudRate,
	})
	if err != nil {
		return nil, err
	}

	return &smartFanUnit{
		rwc: rwc,
		eb:  events.New(),
	}, nil
}

//var ErrCommunicationFailed = errors.New("communication failed") // FIXME: still required or dead code?

const (
	inboundTopic = "smartfanunit:inbound"
	//outboundTopic = "smartfanunit:outbound" // FIXME: still required or dead code?
)

type smartFanUnit struct {
	rwc io.ReadWriteCloser
	mu  sync.Mutex // write mutex

	speed   smartfanunit.FanSpeedRPMPacket
	airflow smartfanunit.AirFlowTemperaturePacket

	eb events.EventBus
}

func (fuc *smartFanUnit) Kind() FanUnitKind {
	return FanUnitKindSmart
}

// Run the client with event loop
func (fuc *smartFanUnit) Run(parentCtx context.Context) error {
	fanUnit.WithLabelValues("smart").Set(1)

	ctx, cancel := context.WithCancelCause(parentCtx)
	defer cancel(nil)

	wg := errgroup.Group{}

	// Start read loop
	wg.Go(func() error {
		for {
			select {
			case <-ctx.Done():
				return nil
			default:
			}

			pkt, err := proto.ReadPacket(ctx, fuc.rwc)
			if err != nil {
				log.FromContext(ctx).WithError(err).Error("Failed to read packet from serial port")
				continue
			}
			fuc.eb.Publish(inboundTopic, pkt)
		}
	})

	// Subscribe to fan speed updates
	wg.Go(func() error {
		sub := fuc.eb.Subscribe(inboundTopic, 1, smartfanunit.MatchCmd(smartfanunit.NotifyFanSpeedRPM))
		defer sub.Unsubscribe()
		for {
			select {
			case <-ctx.Done():
				return nil
			case pktAny := <-sub.C():
				rawPkt := pktAny.(proto.Packet)
				if err := fuc.speed.FromPacket(rawPkt); err != nil && !errors.Is(err, proto.ErrChecksumMismatch) {
					return err
				}
				fanSpeed.Set(float64(fuc.speed.RPM))
			}
		}
	})

	// Subscribe to air flow temperature updates
	wg.Go(func() error {
		sub := fuc.eb.Subscribe(inboundTopic, 1, smartfanunit.MatchCmd(smartfanunit.NotifyAirFlowTemperature))
		defer sub.Unsubscribe()
		for {
			select {
			case <-ctx.Done():
				return nil
			case pktAny := <-sub.C():
				rawPkt := pktAny.(proto.Packet)
				if err := fuc.airflow.FromPacket(rawPkt); err != nil && !errors.Is(err, proto.ErrChecksumMismatch) {
					return err
				}
				airFlowTemperature.Set(float64(fuc.airflow.Temperature))
			}
		}
	})

	return wg.Wait()
}

func (fuc *smartFanUnit) write(ctx context.Context, pktGen smartfanunit.PacketGenerator) error {
	fuc.mu.Lock()
	defer fuc.mu.Unlock()
	return proto.WritePacket(ctx, fuc.rwc, pktGen.Packet())
}

// SetFanSpeedPercent sets the fan speed in percent.
func (fuc *smartFanUnit) SetFanSpeedPercent(ctx context.Context, percent uint8) error {
	return fuc.write(ctx, &smartfanunit.SetFanSpeedPercentPacket{Percent: percent})
}

// SetLed sets the LED color.
func (fuc *smartFanUnit) SetLed(ctx context.Context, color led.Color) error {
	return fuc.write(ctx, &smartfanunit.SetLEDPacket{Color: color})
}

// FanSpeedRPM returns the current fan speed in rotations per minute.
func (fuc *smartFanUnit) FanSpeedRPM(_ context.Context) (float64, error) {
	return float64(fuc.speed.RPM), nil
}

// WaitForButtonPress blocks until the button is pressed.
func (fuc *smartFanUnit) WaitForButtonPress(ctx context.Context) error {
	sub := fuc.eb.Subscribe(inboundTopic, 1, smartfanunit.MatchCmd(smartfanunit.NotifyButtonPress))
	defer sub.Unsubscribe()

	select {
	case <-ctx.Done():
		return ctx.Err()
	case pktAny := <-sub.C():
		rawPkt := pktAny.(proto.Packet)
		if rawPkt.Command != smartfanunit.NotifyButtonPress {
			return errors.New("unexpected packet")
		}
	}

	return nil
}

// AirFlowTemperature returns the temperature of the air flow.
func (fuc *smartFanUnit) AirFlowTemperature(_ context.Context) (float32, error) {
	return fuc.airflow.Temperature, nil
}

func (fuc *smartFanUnit) Close() error {
	return fuc.rwc.Close()
}
