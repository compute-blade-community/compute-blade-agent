# Install, upgrade and remove the agent

The agent runs on Raspberry Pi OS, Debian, Ubuntu, Fedora and Arch Linux for arm64. Every release ships `.deb`, `.rpm`
and Arch packages.

## Install with the install script

The script picks the package format of your distribution, installs the latest release and starts the service:

```bash
curl -L -o /tmp/compute-blade-agent-installer.sh \
  https://raw.githubusercontent.com/compute-blade-community/compute-blade-agent/main/hack/autoinstall.sh
less /tmp/compute-blade-agent-installer.sh   # read it before you run it as root
chmod +x /tmp/compute-blade-agent-installer.sh
/tmp/compute-blade-agent-installer.sh
```

## Install a specific version by hand

Pick the package from the [releases page](https://github.com/compute-blade-community/compute-blade-agent/releases):

```bash
VERSION=0.11.2
curl -LO https://github.com/compute-blade-community/compute-blade-agent/releases/download/v${VERSION}/compute-blade-agent_${VERSION}_linux_arm64.deb
sudo dpkg -i compute-blade-agent_${VERSION}_linux_arm64.deb
sudo systemctl enable --now compute-blade-agent
```

Use `sudo dnf install ./compute-blade-agent_${VERSION}_linux_arm64.rpm` on Fedora and `sudo pacman -U` with the
`.pkg.tar.zst` file on Arch.

Each artifact is signed with cosign (the signature lies next to it on the releases page) and listed in
`compute-blade-agent_<version>_checksums.txt`.

## Check that it runs

```bash
systemctl status compute-blade-agent
sudo bladectl get status
```

## Upgrade

Run the install script again, or install the newer package the same way. Your `/etc/compute-blade-agent/config.yaml`
stays as it is: package managers don't replace a config file you changed. Debian-based systems put the new default
next to it as `config.yaml.dpkg-dist`. Compare the two to find new settings:

```bash
diff /etc/compute-blade-agent/config.yaml /etc/compute-blade-agent/config.yaml.dpkg-dist
```

New settings have defaults, so an old config keeps working. If the agent logs `Deprecated configuration key`, rename
the key it names.

Restart the agent to run the new version:

```bash
sudo systemctl restart compute-blade-agent
```

## Install bladectl on your workstation

`bladectl` releases exist for Linux, macOS and Windows on amd64 and arm64. With [mise](https://mise.jdx.dev):

```bash
mise use -g github:compute-blade-community/compute-blade-agent@0.11.2
```

Or download `bladectl_<version>_<os>_<arch>.tar.gz` from the releases page and put `bladectl` on your `PATH`. Linux
packages are called `bladectl_<version>_linux_<arch>.deb` (and `.rpm`, `.pkg.tar.zst`).

## Remove

```bash
sudo systemctl disable --now compute-blade-agent
sudo apt remove compute-blade-agent        # or: dnf remove, pacman -R
```

The agent's certificates in `/etc/compute-blade-agent/` and root's `~/.config/bladectl/` stay. Delete them to remove
everything:

```bash
sudo rm -rf /etc/compute-blade-agent /root/.config/bladectl
```
