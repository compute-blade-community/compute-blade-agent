#!/bin/bash

set -eu

tmp_dir=$(mktemp -d)
trap 'rm -rf "$tmp_dir"' EXIT

# Function to detect the package suffix based on the available package manager
detect_package_suffix() {
    if [ -x "$(command -v dpkg)" ]; then
        echo "deb"
    elif [ -x "$(command -v dnf)" ]; then
        echo "rpm"
    elif [ -x "$(command -v pacman)" ]; then
        echo "pkg.tar.zst"
    else
        echo "Unsupported package manager" >> /dev/stderr
        exit 1
    fi
}

# Function to get the latest release tag from GitHub
get_latest_release() {
    local repo="$1"
    curl -s "https://api.github.com/repos/$repo/releases/latest" | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/'
}

github_repo="compute-blade-community/compute-blade-agent"
package_suffix=$(detect_package_suffix)
latest_release=$(get_latest_release "$github_repo")

# Create a temporary directory for the download
tmp_dir=$(mktemp -d)

# Construct the download URL and filename based on the detected package manager and latest release
download_url="https://github.com/$github_repo/releases/download/$latest_release/compute-blade-agent_${latest_release#v}_linux_arm64.$package_suffix"
target_file="$tmp_dir/compute-blade-agent.$package_suffix"

# Download the package
echo "Downloading $download_url"
curl -Ls -o "$target_file" "$download_url"

# Install the package
echo "Installing $target_file"
case "$package_suffix" in
    deb)
        sudo dpkg -i "$target_file"
        ;;
    rpm)
        sudo dnf install -y "$target_file"
        ;;
    pkg.tar.zst)
        sudo pacman -U --noconfirm "$target_file"
        ;;
    *)
        echo "Unsupported package format" >> /dev/stderr
        exit 1
        ;;
esac

# Enable and start the service
echo "Enabling and starting compute-blade-agent"
sudo systemctl enable compute-blade-agent --now
