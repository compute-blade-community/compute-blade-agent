//go:build linux && !tinygo

package hal

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/uptime-industries/compute-blade-agent/pkg/hal/led"
	"github.com/uptime-industries/compute-blade-agent/pkg/log"
	"github.com/warthog618/gpiod"
	"github.com/warthog618/gpiod/device/rpi"
	"go.uber.org/zap"
	"golang.org/x/sync/errgroup"
)

const (
	bcm2711PeripheryBaseAddr = 0xFE000000
	bcm2711RegPwmAddr        = bcm2711PeripheryBaseAddr + 0x20C000
	bcm2711GpioAddr          = bcm2711PeripheryBaseAddr + 0x200000
	bcm2711ClkAddr           = bcm2711PeripheryBaseAddr + 0x101000
	bcm2711ClkManagerPwd     = (0x5A << 24) //(31 - 24) on CM_GP0CTL/CM_GP1CTL/CM_GP2CTL regs
	bcm2711PageSize          = 4096         // theoretical page size

	// FIXME: no dead code
	//bcm2711FrontButtonPin = 20
	//bcm2711StealthPin     = 21
	//bcm2711RegPwmTachPin  = 13

	bcm2711RegGpfsel1 = 0x01

	bcm2711RegPwmCtl  = 0x00
	bcm2711RegPwmRng1 = 0x04
	bcm2711RegPwmFif1 = 0x06

	bcm2711RegPwmCtlBitPwen2 = 8 // Enable (pwm2)
	bcm2711RegPwmCtlBitClrf1 = 6 // Clear FIFO
	bcm2711RegPwmCtlBitUsef1 = 5 // Use FIFO
	bcm2711RegPwmCtlBitSbit1 = 3 // Line level when not transmitting
	bcm2711RegPwmCtlBitRptl1 = 2 // Repeat last data when FIFO is empty
	bcm2711RegPwmCtlBitMode1 = 1 // Mode; 0: PWM, 1: Serializer
	bcm2711RegPwmCtlBitPwen1 = 0 // Enable (pwm1)

	bcm2711RegPwmclkCntrl          = 0x28
	bcm2711RegPwmclkDiv            = 0x29
	bcm2711RegPwmclkCntrlBitSrcOsc = 0
	bcm2711RegPwmclkCntrlBitEnable = 4

	bcm2711DebounceInterval = 100 * time.Millisecond

	bcm2711ThermalZonePath = "/sys/class/thermal/thermal_zone0/temp"

	smartFanUnitDev = "/dev/ttyAMA5" // UART5
)

type bcm2711 struct {
	// Config options
	opts ComputeBladeHalOpts

	wrMutex sync.Mutex

	// Keep track of the currently set fanspeed so it can later be restored after setting the ws281x LEDs
	currFanSpeed uint8

	devmem    *os.File
	gpioMem8  []uint8
	gpioMem   []uint32
	pwmMem8   []uint8
	pwmMem    []uint32
	clkMem8   []uint8
	clkMem    []uint32
	gpioChip0 *gpiod.Chip

	// Save LED colors so the pixels can be updated individually
	leds [2]led.Color

	// Stealth mode output
	stealthModeLine *gpiod.Line

	// Edge button input
	edgeButtonLine         *gpiod.Line
	edgeButtonDebounceChan chan struct{}
	edgeButtonWatchChan    chan struct{}

	// PoE detection input
	poeLine *gpiod.Line

	// Fan unit
	fanUnit FanUnit
}

func NewCm4Hal(ctx context.Context, opts ComputeBladeHalOpts) (ComputeBladeHal, error) {
	// /dev/gpiomem doesn't allow complex operations for PWM fan control or WS281x
	devmem, err := os.OpenFile("/dev/mem", os.O_RDWR|os.O_SYNC, os.ModePerm)
	if err != nil {
		return nil, err
	}

	gpioChip0, err := gpiod.NewChip("gpiochip0")
	if err != nil {
		return nil, err
	}

	// Setup memory mappings
	gpioMem, gpioMem8, err := mmap(devmem, bcm2711GpioAddr, bcm2711PageSize)
	if err != nil {
		return nil, err
	}
	pwmMem, pwmMem8, err := mmap(devmem, bcm2711RegPwmAddr, bcm2711PageSize)
	if err != nil {
		return nil, err
	}
	clkMem, clkMem8, err := mmap(devmem, bcm2711ClkAddr, bcm2711PageSize)
	if err != nil {
		return nil, err
	}

	bcm := &bcm2711{
		devmem:                 devmem,
		gpioMem:                gpioMem,
		gpioMem8:               gpioMem8,
		pwmMem:                 pwmMem,
		pwmMem8:                pwmMem8,
		clkMem:                 clkMem,
		clkMem8:                clkMem8,
		gpioChip0:              gpioChip0,
		opts:                   opts,
		edgeButtonDebounceChan: make(chan struct{}, 1),
		edgeButtonWatchChan:    make(chan struct{}),
	}

	computeModule.WithLabelValues("cm4").Set(1)

	log.FromContext(ctx).Info("starting hal setup", zap.String("hal", "bcm2711"))
	err = bcm.setup(ctx)
	if err != nil {
		return nil, err
	}
	return bcm, nil
}

// Close cleans all memory mappings
func (bcm *bcm2711) Close() error {
	errs := errors.Join(
		bcm.fanUnit.Close(),
		syscall.Munmap(bcm.gpioMem8),
		syscall.Munmap(bcm.pwmMem8),
		syscall.Munmap(bcm.clkMem8),
		bcm.devmem.Close(),
		bcm.gpioChip0.Close(),
		bcm.poeLine.Close(),
		bcm.stealthModeLine.Close(),
	)

	return errs
}

// Init initialises GPIOs and sets sane defaults
func (bcm *bcm2711) setup(ctx context.Context) error {
	var err error

	// Register edge event handler for edge button
	bcm.edgeButtonLine, err = bcm.gpioChip0.RequestLine(
		rpi.GPIO20, gpiod.WithEventHandler(bcm.handleEdgeButtonEdge),
		gpiod.WithFallingEdge, gpiod.WithPullUp, gpiod.WithDebounce(50*time.Millisecond))
	if err != nil {
		return err
	}

	// Register input for PoE detection
	bcm.poeLine, err = bcm.gpioChip0.RequestLine(rpi.GPIO23, gpiod.AsInput, gpiod.WithPullUp)
	if err != nil {
		return err
	}

	// Register output for stealth mode
	bcm.stealthModeLine, err = bcm.gpioChip0.RequestLine(rpi.GPIO21, gpiod.AsOutput(1))
	if err != nil {
		return err
	}

	// Setup correct fan unit
	log.FromContext(ctx).Info("detecting fan unit")
	detectCtx, cancel := context.WithTimeout(ctx, 3*time.Second) // temp events are sent every 2 seconds
	defer cancel()

	if smartFanUnitPresent, err := SmartFanUnitPresent(detectCtx, smartFanUnitDev); err == nil && smartFanUnitPresent {
		log.FromContext(ctx).Info("detected smart fan unit")
		bcm.fanUnit, err = NewSmartFanUnit(smartFanUnitDev)
		if err != nil {
			return err
		}
	} else {
		log.FromContext(ctx).WithError(err).Info("no smart fan unit detected, assuming standard fan unit")
		// FAN PWM output for standard fan unit (GPIO 12)
		// -> bcm2711RegGpfsel1 8:6, alt0
		bcm.gpioMem[bcm2711RegGpfsel1] = (bcm.gpioMem[bcm2711RegGpfsel1] &^ (0b111 << 6)) | (0b100 << 6)
		bcm.fanUnit = &standardFanUnitBcm2711{
			GpioChip0:           bcm.gpioChip0,
			DisableRpmReporting: !bcm.opts.RpmReportingStandardFanUnit,
			SetFanSpeedPwmFunc: func(speed uint8) error {
				bcm.setFanSpeedPWM(speed)
				return nil
			},
		}
	}

	return nil
}

func (bcm *bcm2711) Run(parentCtx context.Context) error {
	ctx, cancel := context.WithCancel(parentCtx)
	defer cancel()

	group := errgroup.Group{}

	group.Go(func() error {
		defer cancel()
		return bcm.fanUnit.Run(ctx)
	})

	return group.Wait()
}

func (bcm *bcm2711) handleEdgeButtonEdge(evt gpiod.LineEvent) {
	// Despite debouncing, we still get multiple events for a single button press
	// -> This is an in-software debounce to ensure we only get one event per button press
	select {
	case bcm.edgeButtonDebounceChan <- struct{}{}:
		go func() {
			// Manually debounce the button
			<-bcm.edgeButtonDebounceChan
			time.Sleep(bcm2711DebounceInterval)
			edgeButtonEventCount.Inc()
			close(bcm.edgeButtonWatchChan)
			bcm.edgeButtonWatchChan = make(chan struct{})
		}()
	default:
		// noop
		return
	}
}

// WaitForEdgeButtonPress blocks until the edge button has been pressed
func (bcm *bcm2711) WaitForEdgeButtonPress(parentCtx context.Context) error {
	ctx, cancel := context.WithCancel(parentCtx)
	defer cancel()

	fanUnitChan := make(chan struct{})
	go func() {
		err := bcm.fanUnit.WaitForButtonPress(ctx)
		if err != nil && err != context.Canceled {
			log.FromContext(ctx).WithError(err).Error("failed to wait for button press")
		} else {
			close(fanUnitChan)
		}
	}()

	// Either wait for the context to be cancelled or the edge button to be pressed
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-bcm.edgeButtonWatchChan:
		return nil
	case <-fanUnitChan:
		return nil
	}
}

func (bcm *bcm2711) GetFanRPM() (float64, error) {
	rpm, err := bcm.fanUnit.FanSpeedRPM(context.TODO())
	return float64(rpm), err
}

func (bcm *bcm2711) GetPowerStatus() (PowerStatus, error) {
	// GPIO 23 is used for PoE detection
	val, err := bcm.poeLine.Value()
	if err != nil {
		return PowerPoeOrUsbC, err
	}

	if val > 0 {
		powerStatus.WithLabelValues(fmt.Sprint(PowerPoe802at)).Set(1)
		powerStatus.WithLabelValues(fmt.Sprint(PowerPoeOrUsbC)).Set(0)
		return PowerPoe802at, nil
	}
	powerStatus.WithLabelValues(fmt.Sprint(PowerPoe802at)).Set(0)
	powerStatus.WithLabelValues(fmt.Sprint(PowerPoeOrUsbC)).Set(1)
	return PowerPoeOrUsbC, nil
}

func (bcm *bcm2711) setPwm0Freq(targetFrequency uint64) error {
	// Calculate PWM divisor based on target frequency
	divisor := 54000000 / targetFrequency
	realDivisor := divisor & 0xfff // 12 bits
	if divisor != realDivisor {
		return fmt.Errorf("invalid frequency, max divisor is 4095, calculated divisor is %d", divisor)
	}

	// Stop pwm for both channels; this is required to set the new configuration
	bcm.pwmMem[bcm2711RegPwmCtl] &^= (1 << bcm2711RegPwmCtlBitPwen1) | (1 << bcm2711RegPwmCtlBitPwen2)
	time.Sleep(time.Microsecond * 10)

	// Stop clock w/o any changes, they cannot be made in the same step
	bcm.clkMem[bcm2711RegPwmclkCntrl] = bcm2711ClkManagerPwd | (bcm.clkMem[bcm2711RegPwmclkCntrl] &^ (1 << 4))
	time.Sleep(time.Microsecond * 10)

	// Wait for the clock to not be busy so we can perform the changes
	for bcm.clkMem[bcm2711RegPwmclkCntrl]&(1<<7) != 0 {
		time.Sleep(time.Microsecond * 10)
	}

	// passwd, disabled, source (oscillator)
	bcm.clkMem[bcm2711RegPwmclkCntrl] = bcm2711ClkManagerPwd | (0 << bcm2711RegPwmclkCntrlBitEnable) | (1 << bcm2711RegPwmclkCntrlBitSrcOsc)
	time.Sleep(time.Microsecond * 10)

	bcm.clkMem[bcm2711RegPwmclkDiv] = bcm2711ClkManagerPwd | (uint32(divisor) << 12)
	time.Sleep(time.Microsecond * 10)

	// Start clock (passwd, enable, source)
	bcm.clkMem[bcm2711RegPwmclkCntrl] = bcm2711ClkManagerPwd | (1 << bcm2711RegPwmclkCntrlBitEnable) | (1 << bcm2711RegPwmclkCntrlBitSrcOsc)
	time.Sleep(time.Microsecond * 10)

	// Start pwm for both channels again
	bcm.pwmMem[bcm2711RegPwmCtl] &= (1 << bcm2711RegPwmCtlBitPwen1)
	time.Sleep(time.Microsecond * 10)

	return nil
}

// SetFanSpeed sets the fanspeed of a blade in percent (standard fan unit)
func (bcm *bcm2711) SetFanSpeed(speed uint8) error {
	fanTargetPercent.Set(float64(speed))
	return bcm.fanUnit.SetFanSpeedPercent(context.TODO(), speed)
}

func (bcm *bcm2711) setFanSpeedPWM(speed uint8) {
	// Noctua fans are expecting a 25khz signal, where duty cycle controls fan on/speed/off
	// With the usage of the FIFO, we can alter the duty cycle by the number of bits set in the FIFO, maximum of 32.
	// We therefore need a frequency of 32*25khz = 800khz, which is a divisor of 67.5 (thus we'll use 68).
	// This results in an actual period frequency of 24.8khz, which is within the specifications of Noctua fans.
	err := bcm.setPwm0Freq(800000)
	if err != nil {
		// we know it produces a valid divisor, so this should never happen
		panic(err)
	}

	// Using hardware ticks would offer a better resultion, but this works for now.
	var targetvalue uint32 = 0
	if speed == 0 {
		targetvalue = 0
	} else if speed <= 100 {
		for i := 0; i <= int((float64(speed)/100.0)*32.0); i++ {
			targetvalue |= (1 << i)
		}
	} else {
		targetvalue = ^(uint32(0))
	}

	// Use fifo, repeat, ...
	bcm.pwmMem[bcm2711RegPwmCtl] = (1 << bcm2711RegPwmCtlBitPwen1) | (1 << bcm2711RegPwmCtlBitMode1) | (1 << bcm2711RegPwmCtlBitRptl1) | (1 << bcm2711RegPwmCtlBitUsef1)
	time.Sleep(10 * time.Microsecond)
	bcm.pwmMem[bcm2711RegPwmRng1] = 32
	time.Sleep(10 * time.Microsecond)
	bcm.pwmMem[bcm2711RegPwmFif1] = targetvalue

	// Store fan speed for later use
	bcm.currFanSpeed = speed
}

func (bcm *bcm2711) SetStealthMode(enable bool) error {
	if enable {
		stealthModeEnabled.Set(1)
		return bcm.stealthModeLine.SetValue(1)
	} else {
		stealthModeEnabled.Set(0)
		return bcm.stealthModeLine.SetValue(0)
	}
}

// serializePwmDataFrame converts a byte to a 24 bit PWM data frame for WS281x LEDs
func serializePwmDataFrame(data uint8) uint32 {
	var result uint32 = 0
	for i := 7; i >= 0; i-- {
		if i != 7 {
			result <<= 3
		}
		if (uint32(data)&(1<<i))>>i == 0 {
			result |= 0b100 // -__
		} else {
			result |= 0b110 // --_
		}
	}
	return result
}

func (bcm *bcm2711) SetLed(idx uint, color led.Color) error {
	if idx >= 2 {
		return fmt.Errorf("invalid led index %d, supported: [0, 1]", idx)
	}

	// Update the fan unit LED if the index is the same as the fan unit LED index
	if idx == LedEdge {
		if err := bcm.fanUnit.SetLed(context.TODO(), color); err != nil {
			return err
		}
	}

	bcm.leds[idx] = color

	return bcm.updateLEDs()
}

// updateLEDs sets the color of the WS281x LEDs
func (bcm *bcm2711) updateLEDs() error {
	bcm.wrMutex.Lock()
	defer bcm.wrMutex.Unlock()

	ledColorChangeEventCount.Inc()

	// Set frequency to 3*800khz.
	// we'll bit-bang the data, so we'll need to send 3 bits per one bit of data.
	if err := bcm.setPwm0Freq(3 * 800000); err != nil {
		return err
	}
	time.Sleep(10 * time.Microsecond)

	// WS281x Output (GPIO 18)
	// -> bcm2711RegGpfsel1 24:26, regular output; it's configured as alt5 whenever pixel data is sent.
	// This is not optimal but required as the pwm0 peripheral is shared between fan and data line for the LEDs.
	time.Sleep(10 * time.Microsecond)
	bcm.gpioMem[bcm2711RegGpfsel1] = (bcm.gpioMem[bcm2711RegGpfsel1] &^ (0b111 << 24)) | (0b010 << 24)
	time.Sleep(10 * time.Microsecond)
	defer func() {
		// Set to regular output again so the PWM signal doesn't confuse the WS2812
		bcm.gpioMem[bcm2711RegGpfsel1] = (bcm.gpioMem[bcm2711RegGpfsel1] &^ (0b111 << 24)) | (0b001 << 24)
		bcm.setFanSpeedPWM(bcm.currFanSpeed)
	}()

	bcm.pwmMem[bcm2711RegPwmCtl] = (1 << bcm2711RegPwmCtlBitMode1) | (1 << bcm2711RegPwmCtlBitRptl1) | (0 << bcm2711RegPwmCtlBitSbit1) | (1 << bcm2711RegPwmCtlBitUsef1) | (1 << bcm2711RegPwmCtlBitClrf1)
	time.Sleep(10 * time.Microsecond)
	// bcm.pwmMem[bcm2711RegPwmRng1] = 32
	bcm.pwmMem[bcm2711RegPwmRng1] = 24 // we only need 24 bits per LED
	time.Sleep(10 * time.Microsecond)

	// Add sufficient padding to clear 50us of silence with ~412.5ns per bit -> at least 121 bits -> let's be safe and send 6*24=144 bits of silence
	bcm.pwmMem[bcm2711RegPwmFif1] = 0
	bcm.pwmMem[bcm2711RegPwmFif1] = 0
	bcm.pwmMem[bcm2711RegPwmFif1] = 0
	bcm.pwmMem[bcm2711RegPwmFif1] = 0
	bcm.pwmMem[bcm2711RegPwmFif1] = 0
	bcm.pwmMem[bcm2711RegPwmFif1] = 0
	// Write top LED data
	bcm.pwmMem[bcm2711RegPwmFif1] = serializePwmDataFrame(bcm.leds[0].Red) << 8
	bcm.pwmMem[bcm2711RegPwmFif1] = serializePwmDataFrame(bcm.leds[0].Green) << 8
	bcm.pwmMem[bcm2711RegPwmFif1] = serializePwmDataFrame(bcm.leds[0].Blue) << 8
	// Write edge LED data
	bcm.pwmMem[bcm2711RegPwmFif1] = serializePwmDataFrame(bcm.leds[1].Red) << 8
	bcm.pwmMem[bcm2711RegPwmFif1] = serializePwmDataFrame(bcm.leds[1].Green) << 8
	bcm.pwmMem[bcm2711RegPwmFif1] = serializePwmDataFrame(bcm.leds[1].Blue) << 8
	// make sure there's >50us of silence
	bcm.pwmMem[bcm2711RegPwmFif1] = 0 // auto-repeated, so no need to feed the FIFO further.

	bcm.pwmMem[bcm2711RegPwmCtl] = (1 << bcm2711RegPwmCtlBitPwen1) | (1 << bcm2711RegPwmCtlBitMode1) | (1 << bcm2711RegPwmCtlBitRptl1) | (0 << bcm2711RegPwmCtlBitSbit1) | (1 << bcm2711RegPwmCtlBitUsef1)
	// sleep for 4*50us to ensure the data is sent. This is probably a bit too gracious but does not have a significant impact, so let's be safe data gets out.
	time.Sleep(200 * time.Microsecond)

	return nil
}

// GetTemperature returns the current temperature of the SoC
func (bcm *bcm2711) GetTemperature() (float64, error) {
	// Read temperature

	f, err := os.Open(bcm2711ThermalZonePath)
	if err != nil {
		return -1, err
	}
	raw, err := io.ReadAll(f)
	if err != nil {
		return -1, err
	}

	cpuTemp, err := strconv.Atoi(strings.TrimSpace(string(raw)))
	if err != nil {
		return -1, err
	}

	temp := float64(cpuTemp) / 1000.0
	socTemperature.Set(temp)

	return temp, nil
}
