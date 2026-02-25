#!/bin/bash
# find-tach-gpio.sh - Safely probe GPIOs to find fan tachometer signal
# Run on Radxa node with fan at 100%: sudo ./find-tach-gpio.sh
#
# The tachometer generates 2 pulses per revolution. At 5000 RPM:
#   5000 RPM / 60 = 83.33 RPS * 2 pulses = ~167 Hz
# At 3000 RPM: ~100 Hz
# We look for any GPIO showing periodic edge events.

set -e

PROBE_DURATION=1       # seconds to monitor each GPIO
MIN_EVENTS=10          # minimum events to consider "active" (10 events in 1s = 600 RPM minimum)
DELAY_BETWEEN=0.5      # seconds between probes to let system settle

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo "=== Fan Tachometer GPIO Finder ==="
echo ""

# Check if running as root (needed for gpiomon)
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}Please run as root (sudo)${NC}"
    exit 1
fi

# Check fan speed
FAN_PWM=$(cat /sys/class/hwmon/hwmon8/pwm1 2>/dev/null || echo "unknown")
echo "Current fan PWM: $FAN_PWM (should be 255 for best detection)"
if [ "$FAN_PWM" != "255" ]; then
    echo -e "${YELLOW}Setting fan to 100% for detection...${NC}"
    echo 255 > /sys/class/hwmon/hwmon8/pwm1
    sleep 2  # Let fan spin up
fi
echo ""

# Get list of gpiochips
CHIPS=$(ls /dev/gpiochip* | sed 's|/dev/||')

echo "Scanning GPIO chips: $CHIPS"
echo "Probe duration: ${PROBE_DURATION}s per line, minimum ${MIN_EVENTS} events to flag"
echo ""

FOUND_CANDIDATES=""

for chip in $CHIPS; do
    # Get number of lines for this chip
    NUM_LINES=$(gpioinfo $chip 2>/dev/null | wc -l)
    NUM_LINES=$((NUM_LINES - 1))  # Subtract header line

    if [ "$NUM_LINES" -le 0 ]; then
        continue
    fi

    echo -e "${YELLOW}=== Scanning $chip ($NUM_LINES lines) ===${NC}"

    for line in $(seq 0 $((NUM_LINES - 1))); do
        # Check if line is already in use
        LINE_INFO=$(gpioinfo $chip 2>/dev/null | grep "line *$line:" || true)
        if echo "$LINE_INFO" | grep -q "\[used\]"; then
            # Skip lines that are in use
            continue
        fi

        # Probe the line
        printf "  Line %2d: " "$line"

        # Run gpiomon with timeout, count events
        EVENTS=$(timeout ${PROBE_DURATION}s gpiomon --num-events=100 $chip $line 2>&1 | wc -l || echo "0")

        if [ "$EVENTS" -ge "$MIN_EVENTS" ]; then
            # Calculate approximate frequency
            FREQ=$((EVENTS / PROBE_DURATION))
            RPM_ESTIMATE=$((FREQ * 60 / 2))  # 2 pulses per revolution
            echo -e "${GREEN}ACTIVE! $EVENTS events (~${FREQ} Hz, ~${RPM_ESTIMATE} RPM)${NC}"
            FOUND_CANDIDATES="$FOUND_CANDIDATES\n  $chip line $line: $EVENTS events (~${RPM_ESTIMATE} RPM)"
        elif [ "$EVENTS" -gt 0 ]; then
            echo "$EVENTS events (noise?)"
        else
            echo "no events"
        fi

        # Small delay to let system settle
        sleep $DELAY_BETWEEN
    done
    echo ""
done

echo "=== Scan Complete ==="
if [ -n "$FOUND_CANDIDATES" ]; then
    echo -e "${GREEN}Candidate tachometer GPIOs found:${NC}"
    echo -e "$FOUND_CANDIDATES"
    echo ""
    echo "To verify, try monitoring the candidate with varying fan speeds:"
    echo "  gpiomon --num-events=50 <chip> <line>"
    echo ""
    echo "Then add to device tree or HAL configuration."
else
    echo -e "${YELLOW}No active GPIOs found.${NC}"
    echo "Possible reasons:"
    echo "  - Fan tachometer not connected on this carrier board"
    echo "  - Tachometer uses a different interface (I2C, ADC, etc.)"
    echo "  - Fan doesn't have tachometer wire connected"
fi

# Restore fan to auto if we changed it
if [ "$FAN_PWM" != "255" ] && [ "$FAN_PWM" != "unknown" ]; then
    echo ""
    echo "Restoring fan PWM to $FAN_PWM"
    echo "$FAN_PWM" > /sys/class/hwmon/hwmon8/pwm1
fi
