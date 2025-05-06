// Package emc2101 is a driver for the EMC2101 fan controller
// Based on https://ww1.microchip.com/downloads/en/DeviceDoc/2101.pdf
package emc2101

import (
	"tinygo.org/x/drivers"
)

type emc2101 struct {
	Address uint16
	bus     drivers.I2C
}

// EMC2101 is a driver for the EMC2101 fan controller
type EMC2101 interface {
	// Init initializes the EMC2101
	Init() error
	// InternalTemperature returns the internal temperature of the EMC2101
	InternalTemperature() (float32, error)
	// ExternalTemperature returns the external temperature of the EMC2101
	ExternalTemperature() (float32, error)
	// SetFanPercent sets the fan speed as a percentage of max
	SetFanPercent(percent uint8) error
	// FanRPM returns the current fan speed in RPM
	FanRPM() (float32, error)
}

const (
	// Address is the default I2C address for the EMC2101
	Address               = 0x4C
	ConfigReg             = 0x03
	FanConfigReg          = 0x4a
	FanSpinUpReg          = 0x4b
	FanSettingReg         = 0x4c
	FanTachReadingLowReg  = 0x46
	FanTachReadingHighReg = 0x47
	ExternalTempReg       = 0x01
	InternalTempReg       = 0x00
)

func New(bus drivers.I2C) EMC2101 {
	return &emc2101{bus: bus, Address: Address}
}

// updateReg updates a register with the given set and clear masks
func (e *emc2101) updateReg(regAddr, setMask, clearMask uint8) error {
	buf := make([]uint8, 1)
	err := e.bus.Tx(e.Address, []byte{regAddr}, buf)
	if err != nil {
		return err
	}
	toWrite := buf[0]
	toWrite |= setMask
	toWrite &= ^clearMask

	if toWrite == buf[0] {
		return nil
	}

	return e.bus.Tx(e.Address, []byte{regAddr, toWrite}, nil)
}

func (e *emc2101) Init() error {
	// set pwm mode
	// bit 4: 0 = PWM mode
	// bit 2: 1 = TACH input
	if err := e.updateReg(ConfigReg, (1 << 2), (1 << 4)); err != nil {
		return err
	}

	if err := e.updateReg(FanConfigReg, (1 << 5), 0); err != nil {
		return err
	}

	/*
		0x3 0b100
		0x4b 0b11111
		0x4a 0b100000
		0x4a 0b100000
	*/

	// Configure fan spin up to ignore tach input
	// bit 5: 1 = Ignore tach input for spin up procedure
	if err := e.updateReg(FanSpinUpReg, 0, (1 << 5)); err != nil {
		return err
	}

	return nil
}

func (e *emc2101) InternalTemperature() (float32, error) {
	buf := make([]byte, 1)
	if err := e.bus.Tx(e.Address, []byte{InternalTempReg}, buf); err != nil {
		return 0, err
	}
	return float32(buf[0]), nil
}

func (e *emc2101) ExternalTemperature() (float32, error) {
	buf := make([]byte, 1)
	if err := e.bus.Tx(e.Address, []byte{ExternalTempReg}, buf); err != nil {
		return 0, err
	}
	return float32(buf[0]), nil
}

func (e *emc2101) SetFanPercent(percent uint8) error {
	if percent > 100 {
		percent = 100
	}
	val := uint8(uint32(percent) * 63 / 100)
	return e.bus.Tx(e.Address, []byte{FanSettingReg, val}, nil)
}

func (e *emc2101) FanRPM() (float32, error) {
	high := make([]byte, 1)
	low := make([]byte, 1)

	err := e.bus.Tx(e.Address, []byte{FanTachReadingHighReg}, high)
	if err != nil {
		return 0, err
	}
	err = e.bus.Tx(e.Address, []byte{FanTachReadingLowReg}, low)
	if err != nil {
		return 0, err
	}

	var tachCount = int(high[0])<<8 | int(low[0])

	return float32(5400000) / float32(tachCount), nil
}
