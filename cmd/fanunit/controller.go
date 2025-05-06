//go:build tinygo

package main

import (
	"context"
	"time"

	"machine"

	"github.com/uptime-industries/compute-blade-agent/pkg/events"
	"github.com/uptime-industries/compute-blade-agent/pkg/hal/led"
	"github.com/uptime-industries/compute-blade-agent/pkg/smartfanunit"
	"github.com/uptime-industries/compute-blade-agent/pkg/smartfanunit/emc2101"
	"github.com/uptime-industries/compute-blade-agent/pkg/smartfanunit/proto"
	"golang.org/x/sync/errgroup"
	"tinygo.org/x/drivers"
	"tinygo.org/x/drivers/ws2812"
)

const (
	leftBladeTopicIn   = "left:in"
	leftBladeTopicOut  = "left:out"
	rightBladeTopicIn  = "right:in"
	rightBladeTopicOut = "right:out"
)

type Controller struct {
	DefaultFanSpeed uint8
	LEDs            ws2812.Device
	FanController   emc2101.EMC2101
	ButtonPin       machine.Pin

	LeftUART  drivers.UART
	RightUART drivers.UART

	eb               events.EventBus
	leftLed          led.Color
	rightLed         led.Color
	leftReqFanSpeed  uint8
	rightReqFanSpeed uint8

	buttonPressed int
}

func (c *Controller) Run(parentCtx context.Context) error {
	c.eb = events.New()

	c.FanController.Init()
	c.FanController.SetFanPercent(c.DefaultFanSpeed)
	c.LEDs.Write([]byte{0, 0, 0, 0, 0, 0})

	group, ctx := errgroup.WithContext(parentCtx)

	// LED Update events
	println("[+] Starting LED update loop")
	group.Go(func() error {
		return c.updateLEDs(ctx)
	})

	// Fan speed update events
	println("[+] Starting fan update loop")
	group.Go(func() error {
		return c.updateFanSpeed(ctx)
	})

	// Metric reporting events
	println("[+] Starting metric reporting loop")
	group.Go(func() error {
		return c.metricReporter(ctx)
	})

	// Left blade events
	println("[+] Starting event listener (left)")
	group.Go(func() error {
		return c.listenEvents(ctx, c.LeftUART, leftBladeTopicIn)
	})
	println("[+] Starting event dispatcher (left)")
	group.Go(func() error {
		return c.dispatchEvents(ctx, c.LeftUART, leftBladeTopicOut)
	})

	// right blade events
	println("[+] Starting event listener (right)")
	group.Go(func() error {
		return c.listenEvents(ctx, c.RightUART, rightBladeTopicIn)
	})
	println("[+] Starting event dispatcher (right)")
	group.Go(func() error {
		return c.dispatchEvents(ctx, c.RightUART, rightBladeTopicOut)
	})

	// Button Press events
	println("[+] Starting button interrupt handler")
	c.ButtonPin.SetInterrupt(machine.PinFalling, func(machine.Pin) {
		c.buttonPressed += 1
	})

	group.Go(func() error {
		ticker := time.NewTicker(20 * time.Millisecond)
		for {
			select {
			case <-ctx.Done():
				return nil
			case <-ticker.C:
				btnPressed := smartfanunit.ButtonPressPacket{}
				if c.buttonPressed > 0 {
					// Allow up to 600ms for a 2nc button press
					time.Sleep(600 * time.Millisecond)
				}

				if c.buttonPressed == 1 {
					println("[ ] Button pressed once")
					c.eb.Publish(leftBladeTopicOut, btnPressed.Packet())
				}
				if c.buttonPressed == 2 {
					println("[ ] Button pressed twice")
					c.eb.Publish(rightBladeTopicOut, btnPressed.Packet())
				}
				c.buttonPressed = 0
			}
		}
	})
	return group.Wait()
}

// listenEvents reads events from the UART interface and dispatches them to the events
func (c *Controller) listenEvents(ctx context.Context, uart drivers.UART, targetTopic string) error {
	for {
		// Read packet from UART; blocks until packet is received
		pkt, err := proto.ReadPacket(ctx, uart)
		if err != nil {
			println("[!] failed to read packet, continuing..", err.Error())
			continue
		}
		println("[ ] received packet from UART publishing to topic", targetTopic)
		c.eb.Publish(targetTopic, pkt)
	}
}

// dispatchEvents reads events from the events and writes them to the UART interface
func (c *Controller) dispatchEvents(ctx context.Context, uart drivers.UART, sourceTopic string) error {
	sub := c.eb.Subscribe(sourceTopic, 4, events.MatchAll)
	defer sub.Unsubscribe()
	for {
		select {
		case msg := <-sub.C():
			println("[ ] dispatching event to UART from topic", sourceTopic)
			pkt := msg.(proto.Packet)
			err := proto.WritePacket(ctx, uart, pkt)
			if err != nil {
				println(err.Error())
			}
		case <-ctx.Done():
			return nil
		}
	}
}

func (c *Controller) metricReporter(ctx context.Context) error {
	var err error

	ticker := time.NewTicker(2 * time.Second)
	airFlowTempRight := smartfanunit.AirFlowTemperaturePacket{}
	airFlowTempLeft := smartfanunit.AirFlowTemperaturePacket{}
	fanRpm := smartfanunit.FanSpeedRPMPacket{}
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}

		airFlowTempLeft.Temperature, err = c.FanController.InternalTemperature()
		if err != nil {
			println("[!] failed to read internal temperature:", err.Error())
		}
		airFlowTempRight.Temperature, err = c.FanController.ExternalTemperature()
		if err != nil {
			println("[!] failed to read external temperature:", err.Error())
		}
		fanRpm.RPM, err = c.FanController.FanRPM()
		if err != nil {
			println("[!] failed to read fan RPM:", err.Error())
		}

		// FIXME: This is a workaround for an i2c lockup issue.
		if err != nil {
			println("[!] resetting CPU")
			time.Sleep(100 * time.Millisecond)
			machine.CPUReset()
		}

		// Publish metrics
		c.eb.Publish(leftBladeTopicOut, airFlowTempLeft.Packet())
		c.eb.Publish(rightBladeTopicOut, airFlowTempRight.Packet())
		c.eb.Publish(leftBladeTopicOut, fanRpm.Packet())
		c.eb.Publish(rightBladeTopicOut, fanRpm.Packet())
	}
}

func (c *Controller) updateFanSpeed(ctx context.Context) error {
	var pkt smartfanunit.SetFanSpeedPercentPacket

	subLeft := c.eb.Subscribe(leftBladeTopicIn, 1, events.MatchAll)
	defer subLeft.Unsubscribe()
	subRight := c.eb.Subscribe(rightBladeTopicIn, 1, events.MatchAll)
	defer subRight.Unsubscribe()

	for {
		// Update LED color depending on blade
		select {
		case msg := <-subLeft.C():
			pkt.FromPacket(msg.(proto.Packet))
			c.leftReqFanSpeed = pkt.Percent
		case msg := <-subRight.C():
			pkt.FromPacket(msg.(proto.Packet))
			c.rightReqFanSpeed = pkt.Percent
		case <-ctx.Done():
			return nil
		}

		// Update fan speed with the max requested speed
		if c.leftReqFanSpeed > c.rightReqFanSpeed {
			c.FanController.SetFanPercent(c.leftReqFanSpeed)
		} else {
			c.FanController.SetFanPercent(c.rightReqFanSpeed)
		}
	}
}

func (c *Controller) updateLEDs(ctx context.Context) error {
	subLeft := c.eb.Subscribe(leftBladeTopicIn, 1, smartfanunit.MatchCmd(smartfanunit.CmdSetLED))
	defer subLeft.Unsubscribe()
	subRight := c.eb.Subscribe(rightBladeTopicIn, 1, smartfanunit.MatchCmd(smartfanunit.CmdSetLED))
	defer subRight.Unsubscribe()

	var pkt smartfanunit.SetLEDPacket
	for {
		// Update LED color depending on blade
		select {
		case msg := <-subLeft.C():
			pkt.FromPacket(msg.(proto.Packet))
			c.leftLed = pkt.Color
		case msg := <-subRight.C():
			pkt.FromPacket(msg.(proto.Packet))
			c.rightLed = pkt.Color
		case <-time.After(500 * time.Millisecond):
		case <-ctx.Done():
			return nil
		}
		// Write to LEDs (they are in a chain -> we always have to update both)
		_, err := c.LEDs.Write([]byte{
			c.rightLed.Blue, c.rightLed.Green, c.rightLed.Red,
			c.leftLed.Blue, c.leftLed.Green, c.leftLed.Red,
		})
		if err != nil {
			println("[!] failed to update LEDs", err.Error())
			return err
		}
	}
}
