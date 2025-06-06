//go:build !tinygo

package hal_test

import (
	"context"
	"log"

	"github.com/compute-blade-community/compute-blade-agent/pkg/hal"
	"github.com/compute-blade-community/compute-blade-agent/pkg/hal/led"
)

func ExampleNewSmartFanUnit() {
	ctx := context.Background()

	client, err := hal.NewSmartFanUnit("/dev/tty.usbmodem11102")
	if err != nil {
		panic(err)
	}
	go func() {
		err := client.Run(ctx)
		if err != nil {
			panic(err)
		}
	}()

	// Set LED color for the blade to red
	err = client.SetLed(ctx, led.Color{Red: 100, Green: 0, Blue: 0})
	if err != nil {
		panic(err)
	}

	// Set fan speed to 20%
	err = client.SetFanSpeedPercent(ctx, 20)
	if err != nil {
		panic(err)
	}

	tmp, err := client.AirFlowTemperature(ctx)
	if err != nil {
		panic(err)
	}
	log.Println("AirflowTemp", tmp)
	rpm, err := client.FanSpeedRPM(ctx)
	if err != nil {
		panic(err)
	}
	log.Println("RPM", rpm)
}
