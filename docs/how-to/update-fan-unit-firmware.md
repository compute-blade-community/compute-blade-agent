# Update the smart fan unit firmware

The firmware of the smart fan unit comes with the agent. Each release installs the matching build at
`/usr/share/compute-blade-agent/fanunit.uf2`, and it's attached to the
[release](https://github.com/compute-blade-community/compute-blade-agent/releases/latest) as `fanunit.uf2`.

1. Copy the firmware to a machine with a USB port:

   ```bash
   scp blade-pi1:/usr/share/compute-blade-agent/fanunit.uf2 .
   ```

2. Put the fan unit's RP2040 into boot mode and copy `fanunit.uf2` to the drive it shows up as. The fan unit's
   [update instructions](https://docs.computeblade.com/fan-unit/uart#update-firmware) show where the boot button is.

3. Restart the agents of both blades the fan unit serves, so they detect it again:

   ```bash
   sudo systemctl restart compute-blade-agent
   journalctl -u compute-blade-agent | grep 'detected smart fan unit'
   ```

Until a blade sends it a speed, the fan unit runs the fan at 40%.
