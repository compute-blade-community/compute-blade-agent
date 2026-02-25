//go:build linux && !tinygo

package hal

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/compute-blade-community/compute-blade-agent/pkg/hal/led"
	"github.com/compute-blade-community/compute-blade-agent/pkg/log"
	"github.com/warthog618/gpiod"
	"github.com/warthog618/gpiod/device/rpi"
	"go.uber.org/zap"
	"golang.org/x/sync/errgroup"
)

const (
	// RP1 southbridge is connected via PCIe on BCM2712.
	// The BAR base address is fixed by firmware at 0x1f00000000.
	rp1BarBase  int64 = 0x1f00000000
	rp1GpioBase int64 = rp1BarBase + 0xd0000
	rp1Pwm0Base int64 = rp1BarBase + 0x98000
	rp1PageSize       = 4096

	// RP1 PWM input clock is 50 MHz (from device tree assigned-clock-rates)
	rp1PwmClockHz = 50_000_000

	// RP1 GPIO register layout: each GPIO has 8 bytes (STATUS + CTRL)
	rp1GpioCtrlOffset  = 0x04 // CTRL register offset within each GPIO's 8-byte block
	rp1GpioRegSize     = 0x08
	rp1GpioFuncselMask = 0x1f // CTRL bits [4:0]

	// GPIO function select values (confirmed via `pinctrl set/get` on CM5)
	// GPIO 12: funcsel 0 (a0) = PWM0_CHAN0 (fan PWM)
	// GPIO 18: funcsel 3 (a3) = PWM0_CHAN2 (WS281x LEDs)
	rp1Gpio12FuncselPwm = 0
	rp1Gpio18FuncselPwm = 3
	rp1GpioFuncselSio   = 5    // Software IO (standard GPIO)
	rp1GpioFuncselNull  = 0x1f // Null function (disabled)

	// RP1 PWM register offsets (byte offsets, divide by 4 for []uint32 index)
	rp1PwmGlobalCtrl = 0x00
	rp1PwmFifoCtrl   = 0x04
	rp1PwmFifoPush   = 0x08
	rp1PwmFifoLevel  = 0x0c

	// Per-channel registers: base = 0x14 + channel * 0x10
	// From kernel pwm-rp1.c: CTRL(x)=0x14+x*16, RANGE(x)=0x18+x*16, DUTY(x)=0x20+x*16
	rp1PwmChanCtrlOff  = 0x00 // relative to channel base
	rp1PwmChanRangeOff = 0x04
	rp1PwmChanPhaseOff = 0x08 // undocumented in kernel driver, possibly COUNT
	rp1PwmChanDutyOff  = 0x0c
	rp1PwmChanSize     = 0x10
	rp1PwmChanBase     = 0x14 // first channel base offset (NOT 0x10)

	// PWM global ctrl bits (from kernel pwm-rp1.c)
	rp1PwmGlobalChanEnBit  = 0  // bits [3:0] = per-channel enable, BIT(x)
	rp1PwmGlobalSetUpdate  = 31 // BIT(31) = global set_update trigger

	// PWM channel ctrl bits
	rp1PwmChanCtrlModeBit        = 0 // bits [1:0]
	rp1PwmChanCtrlInvertBit      = 2
	rp1PwmChanCtrlUseFifoBit     = 4
	rp1PwmChanCtrlFifoPopMaskBit = 7 // bits [8:7]

	// PWM modes
	rp1PwmModeTrailingEdge = 0
	rp1PwmModeMarkSpace    = 1
	rp1PwmModeSerializer   = 3

	// FIFO ctrl bits
	rp1PwmFifoFlushBit = 5

	// Fan PWM: 25 kHz for Noctua fans
	// RANGE = 50 MHz / 25 kHz = 2000
	rp1FanPwmRange = rp1PwmClockHz / 25000

	bcm2712SmartFanUnitDev  = "/dev/ttyAMA4" // UART4 on BCM2712 (same GPIO 12/13 pins as UART5 on BCM2711)
	bcm2712ThermalZonePath  = "/sys/class/thermal/thermal_zone0/temp"
	bcm2712DebounceInterval = 100 * time.Millisecond

	// WS281x LED encoding for RP1 at 50MHz with RANGE=32 serializer mode.
	// Each WS281x data bit is encoded as 2 × 32-bit FIFO words (1280ns per bit ≈ 781kHz).
	// Channel 2 on GPIO 18 is used independently from fan PWM on channel 0.
	rp1Ws281xChan  = 2  // PWM0 channel 2 on GPIO 18
	rp1Ws281xRange = 32 // full 32-bit word in serializer mode

	// "0" bit: T0H=400ns (20 high bits), T0L=880ns (44 low bits)
	rp1Ws281xBit0Word0 uint32 = 0xFFFFF000
	rp1Ws281xBit0Word1 uint32 = 0x00000000
	// "1" bit: T1H=800ns (40 high bits), T1L=480ns (24 low bits)
	rp1Ws281xBit1Word0 uint32 = 0xFFFFFFFF
	rp1Ws281xBit1Word1 uint32 = 0xFF000000

	// Reset: >50μs of low. At 640ns/word, 80 words = 51.2μs.
	rp1Ws281xResetWords = 80
	// Conservative FIFO depth assumption (BCM2835 has 16, RP1 may differ)
	rp1Ws281xFifoMax uint32 = 8
	// Safety timeout for FIFO operations
	rp1Ws281xTimeout = 5 * time.Millisecond
)

// pwmChanRegIdx returns the []uint32 index for a per-channel register.
func pwmChanRegIdx(channel, regOffset int) int {
	return (rp1PwmChanBase + channel*rp1PwmChanSize + regOffset) / 4
}

type bcm2712 struct {
	opts ComputeBladeHalOpts

	wrMutex sync.Mutex

	currFanSpeed uint8

	devmem   *os.File
	gpioMem8 []uint8
	gpioMem  []uint32
	pwmMem8  []uint8
	pwmMem   []uint32

	gpioChip0 *gpiod.Chip

	// WS281x LED colors (top + edge)
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

func newBcm2712Hal(ctx context.Context, opts ComputeBladeHalOpts) (ComputeBladeHal, error) {
	devmem, err := os.OpenFile("/dev/mem", os.O_RDWR|os.O_SYNC, os.ModePerm)
	if err != nil {
		return nil, fmt.Errorf("failed to open /dev/mem: %w", err)
	}

	gpioChip0, err := gpiod.NewChip("gpiochip0")
	if err != nil {
		devmem.Close()
		return nil, fmt.Errorf("failed to open gpiochip0: %w", err)
	}

	// Memory-map RP1 GPIO bank 0 (GPIOs 0-27)
	gpioMem, gpioMem8, err := mmap(devmem, rp1GpioBase, rp1PageSize)
	if err != nil {
		gpioChip0.Close()
		devmem.Close()
		return nil, fmt.Errorf("failed to mmap RP1 GPIO at 0x%x: %w", rp1GpioBase, err)
	}

	// Memory-map RP1 PWM0
	pwmMem, pwmMem8, err := mmap(devmem, rp1Pwm0Base, rp1PageSize)
	if err != nil {
		syscall.Munmap(gpioMem8)
		gpioChip0.Close()
		devmem.Close()
		return nil, fmt.Errorf("failed to mmap RP1 PWM0 at 0x%x: %w", rp1Pwm0Base, err)
	}

	bcm := &bcm2712{
		devmem:                 devmem,
		gpioMem:                gpioMem,
		gpioMem8:               gpioMem8,
		pwmMem:                 pwmMem,
		pwmMem8:                pwmMem8,
		gpioChip0:              gpioChip0,
		opts:                   opts,
		edgeButtonDebounceChan: make(chan struct{}, 1),
		edgeButtonWatchChan:    make(chan struct{}),
	}

	computeModule.WithLabelValues("cm5").Set(1)

	log.FromContext(ctx).Info("starting hal setup", zap.String("hal", "bcm2712"))
	if err := bcm.setup(ctx); err != nil {
		bcm.Close()
		return nil, err
	}
	return bcm, nil
}

func (bcm *bcm2712) Close() error {
	errs := errors.Join(
		bcm.closeFanUnit(),
		bcm.unmapMem(),
		bcm.closeDevmem(),
		bcm.closeGpio(),
	)
	return errs
}

func (bcm *bcm2712) closeFanUnit() error {
	if bcm.fanUnit != nil {
		return bcm.fanUnit.Close()
	}
	return nil
}

func (bcm *bcm2712) unmapMem() error {
	return errors.Join(
		munmapIfNonNil(bcm.gpioMem8),
		munmapIfNonNil(bcm.pwmMem8),
	)
}

func munmapIfNonNil(mem []uint8) error {
	if mem != nil {
		return syscall.Munmap(mem)
	}
	return nil
}

func (bcm *bcm2712) closeDevmem() error {
	if bcm.devmem != nil {
		return bcm.devmem.Close()
	}
	return nil
}

func (bcm *bcm2712) closeGpio() error {
	var errs []error
	if bcm.gpioChip0 != nil {
		errs = append(errs, bcm.gpioChip0.Close())
	}
	if bcm.poeLine != nil {
		errs = append(errs, bcm.poeLine.Close())
	}
	if bcm.stealthModeLine != nil {
		errs = append(errs, bcm.stealthModeLine.Close())
	}
	return errors.Join(errs...)
}

// setGpioFuncsel sets the function select for a GPIO pin via direct register write.
func (bcm *bcm2712) setGpioFuncsel(gpio int, funcsel uint32) {
	ctrlIdx := (gpio*rp1GpioRegSize + rp1GpioCtrlOffset) / 4
	ctrl := bcm.gpioMem[ctrlIdx]
	ctrl = (ctrl &^ uint32(rp1GpioFuncselMask)) | (funcsel & uint32(rp1GpioFuncselMask))
	bcm.gpioMem[ctrlIdx] = ctrl
}

func (bcm *bcm2712) setup(ctx context.Context) error {
	var err error

	// Register edge event handler for edge button (GPIO 20)
	bcm.edgeButtonLine, err = bcm.gpioChip0.RequestLine(
		rpi.GPIO20, gpiod.WithEventHandler(bcm.handleEdgeButtonEdge),
		gpiod.WithFallingEdge, gpiod.WithPullUp, gpiod.WithDebounce(50*time.Millisecond))
	if err != nil {
		return fmt.Errorf("failed to request GPIO20 (edge button): %w", err)
	}

	// Register input for PoE detection (GPIO 23)
	bcm.poeLine, err = bcm.gpioChip0.RequestLine(rpi.GPIO23, gpiod.AsInput, gpiod.WithPullUp)
	if err != nil {
		return fmt.Errorf("failed to request GPIO23 (PoE detect): %w", err)
	}

	// Register output for stealth mode (GPIO 21)
	bcm.stealthModeLine, err = bcm.gpioChip0.RequestLine(rpi.GPIO21, gpiod.AsOutput(1))
	if err != nil {
		return fmt.Errorf("failed to request GPIO21 (stealth mode): %w", err)
	}

	// Detect fan unit type
	log.FromContext(ctx).Info("detecting fan unit")
	detectCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	if smartFanUnitPresent, err := SmartFanUnitPresent(detectCtx, bcm2712SmartFanUnitDev); err == nil && smartFanUnitPresent {
		log.FromContext(ctx).Info("detected smart fan unit")
		bcm.fanUnit, err = NewSmartFanUnit(bcm2712SmartFanUnitDev)
		if err != nil {
			return fmt.Errorf("failed to create smart fan unit: %w", err)
		}
	} else {
		log.FromContext(ctx).WithError(err).Info("no smart fan unit detected, assuming standard fan unit")

		// Set GPIO 12 to PWM0_CHAN0 function
		bcm.setGpioFuncsel(12, rp1Gpio12FuncselPwm)

		// Initialize PWM0 channel 0 for fan control (25 kHz mark-space)
		bcm.initFanPwm()

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

// initFanPwm configures PWM0 channel 0 in mark-space mode at 25 kHz.
func (bcm *bcm2712) initFanPwm() {
	ch := 0

	// Disable channel 0
	globalCtrl := bcm.pwmMem[rp1PwmGlobalCtrl/4]
	globalCtrl &^= (1 << (rp1PwmGlobalChanEnBit + ch))
	bcm.pwmMem[rp1PwmGlobalCtrl/4] = globalCtrl
	time.Sleep(10 * time.Microsecond)

	// Configure channel 0: mark-space mode, no FIFO, no invert
	bcm.pwmMem[pwmChanRegIdx(ch, rp1PwmChanCtrlOff)] = uint32(rp1PwmModeMarkSpace) << rp1PwmChanCtrlModeBit
	time.Sleep(10 * time.Microsecond)

	// Set range (period) for 25 kHz
	bcm.pwmMem[pwmChanRegIdx(ch, rp1PwmChanRangeOff)] = rp1FanPwmRange
	time.Sleep(10 * time.Microsecond)

	// Set initial duty to 0 (fan off)
	bcm.pwmMem[pwmChanRegIdx(ch, rp1PwmChanDutyOff)] = 0
	time.Sleep(10 * time.Microsecond)

	// Phase = 0
	bcm.pwmMem[pwmChanRegIdx(ch, rp1PwmChanPhaseOff)] = 0
	time.Sleep(10 * time.Microsecond)

	// Trigger update for channel 0
	globalCtrl = bcm.pwmMem[rp1PwmGlobalCtrl/4]
	globalCtrl |= (1 << rp1PwmGlobalSetUpdate)
	bcm.pwmMem[rp1PwmGlobalCtrl/4] = globalCtrl
	time.Sleep(10 * time.Microsecond)

	// Enable channel 0
	globalCtrl = bcm.pwmMem[rp1PwmGlobalCtrl/4]
	globalCtrl |= (1 << (rp1PwmGlobalChanEnBit + ch))
	bcm.pwmMem[rp1PwmGlobalCtrl/4] = globalCtrl
	time.Sleep(10 * time.Microsecond)
}

func (bcm *bcm2712) Run(parentCtx context.Context) error {
	ctx, cancel := context.WithCancel(parentCtx)
	defer cancel()

	group := errgroup.Group{}

	group.Go(func() error {
		defer cancel()
		return bcm.fanUnit.Run(ctx)
	})

	return group.Wait()
}

func (bcm *bcm2712) handleEdgeButtonEdge(evt gpiod.LineEvent) {
	select {
	case bcm.edgeButtonDebounceChan <- struct{}{}:
		go func() {
			<-bcm.edgeButtonDebounceChan
			time.Sleep(bcm2712DebounceInterval)
			edgeButtonEventCount.Inc()
			close(bcm.edgeButtonWatchChan)
			bcm.edgeButtonWatchChan = make(chan struct{})
		}()
	default:
		return
	}
}

func (bcm *bcm2712) WaitForEdgeButtonPress(parentCtx context.Context) error {
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

	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-bcm.edgeButtonWatchChan:
		return nil
	case <-fanUnitChan:
		return nil
	}
}

func (bcm *bcm2712) GetFanRPM() (float64, error) {
	rpm, err := bcm.fanUnit.FanSpeedRPM(context.TODO())
	return float64(rpm), err
}

func (bcm *bcm2712) GetPowerStatus() (PowerStatus, error) {
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

// SetFanSpeed sets the fan speed in percent.
func (bcm *bcm2712) SetFanSpeed(speed uint8) error {
	fanTargetPercent.Set(float64(speed))
	return bcm.fanUnit.SetFanSpeedPercent(context.TODO(), speed)
}

// setFanSpeedPWM sets the fan PWM duty cycle using RP1 PWM0 channel 0 in mark-space mode.
func (bcm *bcm2712) setFanSpeedPWM(speed uint8) {
	ch := 0

	var duty uint32
	if speed == 0 {
		duty = 0
	} else if speed <= 100 {
		duty = uint32(float64(rp1FanPwmRange) * float64(speed) / 100.0)
	} else {
		duty = rp1FanPwmRange
	}

	// Update duty cycle
	bcm.pwmMem[pwmChanRegIdx(ch, rp1PwmChanDutyOff)] = duty

	// Trigger update
	globalCtrl := bcm.pwmMem[rp1PwmGlobalCtrl/4]
	globalCtrl |= (1 << rp1PwmGlobalSetUpdate)
	bcm.pwmMem[rp1PwmGlobalCtrl/4] = globalCtrl

	bcm.currFanSpeed = speed
}

func (bcm *bcm2712) SetStealthMode(enable bool) error {
	if enable {
		stealthModeEnabled.Set(1)
		return bcm.stealthModeLine.SetValue(1)
	}
	stealthModeEnabled.Set(0)
	return bcm.stealthModeLine.SetValue(0)
}

func (bcm *bcm2712) StealthModeActive() bool {
	val, err := bcm.stealthModeLine.Value()
	if err != nil {
		return false
	}
	return val > 0
}

// SetLed sets the WS281x LED color via RP1 PWM0 channel 2 serializer mode.
// Unlike BCM2711 which shares PWM0 between fan and LEDs, RP1 has independent channels:
// channel 0 (GPIO 12) handles fan PWM, channel 2 (GPIO 18) handles WS281x LEDs.
func (bcm *bcm2712) SetLed(idx LedIndex, color led.Color) error {
	if idx >= 2 {
		return fmt.Errorf("invalid led index %d, supported: [0, 1]", idx)
	}

	// Update the fan unit LED if this is the edge LED
	if idx == LedEdge {
		if err := bcm.fanUnit.SetLed(context.TODO(), color); err != nil {
			return err
		}
	}

	bcm.leds[idx] = color

	return bcm.updateLEDs()
}

// updateLEDs sends WS281x data via RP1 PWM0 channel 2 serializer mode.
// Uses the shared FIFO (channel 0 fan PWM uses mark-space mode without FIFO, so no conflict).
// The RP1 PWM clock is fixed at 50MHz, so we use 2 FIFO words per WS281x data bit
// at RANGE=32 to achieve ~1280ns per bit (within WS281x tolerance).
func (bcm *bcm2712) updateLEDs() error {
	bcm.wrMutex.Lock()
	defer bcm.wrMutex.Unlock()

	ledColorChangeEventCount.Inc()

	ch := rp1Ws281xChan

	// Build complete FIFO data stream
	data := bcm.buildWs281xStream()

	// Set GPIO 18 to PWM0_CH2 function
	bcm.setGpioFuncsel(18, rp1Gpio18FuncselPwm)
	time.Sleep(10 * time.Microsecond)

	// Disable channel 2
	globalCtrl := bcm.pwmMem[rp1PwmGlobalCtrl/4]
	globalCtrl &^= (1 << (rp1PwmGlobalChanEnBit + ch))
	bcm.pwmMem[rp1PwmGlobalCtrl/4] = globalCtrl
	time.Sleep(10 * time.Microsecond)

	// Configure channel 2: serializer mode, use FIFO, SBIT=0 (low when idle)
	bcm.pwmMem[pwmChanRegIdx(ch, rp1PwmChanCtrlOff)] =
		(rp1PwmModeSerializer << rp1PwmChanCtrlModeBit) | (1 << rp1PwmChanCtrlUseFifoBit)
	bcm.pwmMem[pwmChanRegIdx(ch, rp1PwmChanRangeOff)] = rp1Ws281xRange
	bcm.pwmMem[pwmChanRegIdx(ch, rp1PwmChanPhaseOff)] = 0
	time.Sleep(10 * time.Microsecond)

	// Flush FIFO
	bcm.pwmMem[rp1PwmFifoCtrl/4] = (1 << rp1PwmFifoFlushBit)
	time.Sleep(10 * time.Microsecond)

	// Trigger update for channel 2
	globalCtrl = bcm.pwmMem[rp1PwmGlobalCtrl/4]
	globalCtrl |= (1 << rp1PwmGlobalSetUpdate)
	bcm.pwmMem[rp1PwmGlobalCtrl/4] = globalCtrl
	time.Sleep(10 * time.Microsecond)

	// Pre-fill FIFO before enabling channel
	idx := 0
	for idx < len(data) && uint32(idx) < rp1Ws281xFifoMax {
		bcm.pwmMem[rp1PwmFifoPush/4] = data[idx]
		idx++
	}

	// Lock OS thread for tight FIFO feeding
	runtime.LockOSThread()

	// Enable channel 2
	globalCtrl = bcm.pwmMem[rp1PwmGlobalCtrl/4]
	globalCtrl |= (1 << (rp1PwmGlobalChanEnBit + ch))
	bcm.pwmMem[rp1PwmGlobalCtrl/4] = globalCtrl

	// Push remaining data, polling FIFO level to avoid overflow
	fifoLevelReg := rp1PwmFifoLevel / 4
	fifoPushReg := rp1PwmFifoPush / 4
	deadline := time.Now().Add(rp1Ws281xTimeout)

	for idx < len(data) {
		if time.Now().After(deadline) {
			break
		}
		if bcm.pwmMem[fifoLevelReg] < rp1Ws281xFifoMax {
			bcm.pwmMem[fifoPushReg] = data[idx]
			idx++
		}
	}

	// Wait for FIFO to drain
	for bcm.pwmMem[fifoLevelReg] > 0 {
		if time.Now().After(deadline) {
			break
		}
	}

	runtime.UnlockOSThread()

	// Wait for last word to finish shifting out
	time.Sleep(200 * time.Microsecond)

	// Disable channel 2
	globalCtrl = bcm.pwmMem[rp1PwmGlobalCtrl/4]
	globalCtrl &^= (1 << (rp1PwmGlobalChanEnBit + ch))
	bcm.pwmMem[rp1PwmGlobalCtrl/4] = globalCtrl

	// Disconnect GPIO 18 from PWM to prevent residual noise on the data line
	bcm.setGpioFuncsel(18, rp1GpioFuncselNull)

	return nil
}

// buildWs281xStream constructs the complete FIFO word stream for both WS281x LEDs.
// Format: [reset padding] [top LED RGB] [edge LED RGB] [trailing zeros]
func (bcm *bcm2712) buildWs281xStream() []uint32 {
	// Pre-allocate: 80 reset + 96 data (2 LEDs × 3 bytes × 16 words) + 2 trailing
	words := make([]uint32, 0, rp1Ws281xResetWords+96+2)

	// Reset padding (>50μs of low signal)
	for i := 0; i < rp1Ws281xResetWords; i++ {
		words = append(words, 0)
	}

	// Top LED (index 0) - RGB order (matches BCM2711 upstream)
	words = appendByteWs281x(words, bcm.leds[0].Red)
	words = appendByteWs281x(words, bcm.leds[0].Green)
	words = appendByteWs281x(words, bcm.leds[0].Blue)

	// Edge LED (index 1)
	words = appendByteWs281x(words, bcm.leds[1].Red)
	words = appendByteWs281x(words, bcm.leds[1].Green)
	words = appendByteWs281x(words, bcm.leds[1].Blue)

	// Trailing zeros for clean end-of-frame
	words = append(words, 0, 0)

	return words
}

// appendByteWs281x encodes one byte as 16 FIFO words (2 per data bit, MSB first) for RP1 WS281x.
func appendByteWs281x(words []uint32, b uint8) []uint32 {
	for i := 7; i >= 0; i-- {
		if (b>>uint(i))&1 == 0 {
			words = append(words, rp1Ws281xBit0Word0, rp1Ws281xBit0Word1)
		} else {
			words = append(words, rp1Ws281xBit1Word0, rp1Ws281xBit1Word1)
		}
	}
	return words
}

// GetTemperature returns the SoC temperature in degrees Celsius.
func (bcm *bcm2712) GetTemperature() (float64, error) {
	f, err := os.Open(bcm2712ThermalZonePath)
	if err != nil {
		return -1, err
	}
	defer f.Close()

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
