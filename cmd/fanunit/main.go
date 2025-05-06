//go:build tinygo

package main

import (
	"context"
	"time"

	"machine"

	"github.com/uptime-industries/compute-blade-agent/pkg/smartfanunit"
	"github.com/uptime-industries/compute-blade-agent/pkg/smartfanunit/emc2101"
	"tinygo.org/x/drivers/ws2812"
)

func main() {
	var controller *Controller
	var emc emc2101.EMC2101
	var bgrLeds ws2812.Device
	var err error

	// Configure status LED
	machine.LED.Configure(machine.PinConfig{Mode: machine.PinOutput})
	machine.LED.Set(false)

	// Configure UARTs
	err = machine.UART0.Configure(machine.UARTConfig{TX: machine.UART0_TX_PIN, RX: machine.UART0_RX_PIN})
	if err != nil {
		println("[!] Failed to initialize UART0:", err.Error())
		goto errPrint
	}
	machine.UART0.SetBaudRate(smartfanunit.BaudRate)
	err = machine.UART1.Configure(machine.UARTConfig{TX: machine.UART1_TX_PIN, RX: machine.UART1_RX_PIN})
	if err != nil {
		println("[!] Failed to initialize UART1:", err.Error())
		goto errPrint
	}
	machine.UART1.SetBaudRate(smartfanunit.BaudRate)

	// Enables fan, DO NOT CHANGE
	machine.GP16.Configure(machine.PinConfig{Mode: machine.PinOutput})
	machine.GP16.Set(true)

	// WS2812 LEDs
	machine.GP15.Configure(machine.PinConfig{Mode: machine.PinOutput})
	bgrLeds = ws2812.New(machine.GP15)

	// Configure button
	machine.GP12.Configure(machine.PinConfig{Mode: machine.PinInput})

	// Setup emc2101
	machine.I2C0.Configure(machine.I2CConfig{
		Frequency: 100 * machine.KHz,
		SDA:       machine.I2C0_SDA_PIN,
		SCL:       machine.I2C0_SCL_PIN,
	})
	emc = emc2101.New(machine.I2C0)
	err = emc.Init()
	if err != nil {
		println("[!] Failed to initialize emc2101:", err.Error())
		goto errPrint
	}

	println("[+] IO initialized, starting controller...")

	// Run controller
	controller = &Controller{
		DefaultFanSpeed: 40,
		LEDs:            bgrLeds,
		FanController:   emc,
		ButtonPin:       machine.GP12,
		LeftUART:        machine.UART0,
		RightUART:       machine.UART1,
	}

	err = controller.Run(context.Background())

	// Blinking -> something went wrong
errPrint:
	ledState := false
	for {
		ledState = !ledState
		machine.LED.Set(ledState)
		// Repeat error message
		println("[FATAL] controller exited with error:", err)
		time.Sleep(500 * time.Millisecond)
	}
}
