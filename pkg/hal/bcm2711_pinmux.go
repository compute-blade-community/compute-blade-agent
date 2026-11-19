package hal

// GPFSEL1 holds the function of GPIO 10-19, three bits per pin.
const (
	bcm2711GpfselBits   = 3
	bcm2711GpfselMask   = 0b111
	bcm2711GpfselAlt0   = 0b100
	bcm2711GpfselAlt4   = 0b011
	bcm2711Gpfsel1First = 10 // first GPIO in GPFSEL1
)

// withGpioFunction returns the GPFSEL1 value with pin set to fn.
func withGpioFunction(gpfsel1 uint32, pin int, fn uint32) uint32 {
	shift := uint32(pin-bcm2711Gpfsel1First) * bcm2711GpfselBits
	return (gpfsel1 &^ (bcm2711GpfselMask << shift)) | (fn << shift)
}

// withUart5Pins returns the GPFSEL1 value with GPIO 12 and 13 on UART5 (TXD5/RXD5, alt4), the smart fan unit's serial
// port (/dev/ttyAMA5).
func withUart5Pins(gpfsel1 uint32) uint32 {
	return withGpioFunction(withGpioFunction(gpfsel1, 12, bcm2711GpfselAlt4), 13, bcm2711GpfselAlt4)
}

// withPwmFanPin returns the GPFSEL1 value with GPIO 12 on PWM0 channel 0 (alt0), the standard fan unit's PWM.
func withPwmFanPin(gpfsel1 uint32) uint32 {
	return withGpioFunction(gpfsel1, 12, bcm2711GpfselAlt0)
}
