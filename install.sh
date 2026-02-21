#!/bin/bash

# Installation script for mypwd password manager
# Compatible with Linux and macOS

set -e

echo "Installing mypwd password manager..."

# Detect OS
OS="$(uname -s)"
case "$OS" in
    Linux*)     OS_TYPE=Linux;;
    Darwin*)    OS_TYPE=Mac;;
    *)          OS_TYPE="UNKNOWN:$OS"
esac

echo "Detected OS: $OS_TYPE"

# Check Python version
if ! command -v python3 &> /dev/null; then
    echo "Error: Python 3 is required but not installed."
    exit 1
fi

PYTHON_VERSION=$(python3 --version 2>&1 | awk '{print $2}')
echo "Python version: $PYTHON_VERSION"

# Install dependencies
echo "Installing dependencies from pinned requirements..."

if [ "$OS_TYPE" = "Mac" ]; then
    # macOS specific installation
    if command -v brew &> /dev/null; then
        echo "Homebrew detected. Installing system dependencies if needed..."
        # Ensure pip is available
        python3 -m ensurepip --default-pip 2>/dev/null || true
    fi
    
    # Install Python packages
    python3 -m pip install -r requirements.txt
    
    # Check for clipboard support
    if ! command -v pbcopy &> /dev/null; then
        echo "Warning: pbcopy not found. Clipboard may not work properly."
    fi
else
    # Linux specific installation
    # Install Python packages
    pip3 install --user -r requirements.txt
    
    # Check for clipboard utilities
    if ! command -v xclip &> /dev/null && ! command -v xsel &> /dev/null; then
        echo ""
        echo "Warning: No clipboard utility detected (xclip or xsel)."
        echo "For clipboard support, install one of:"
        if command -v apt-get &> /dev/null; then
            echo "  sudo apt-get install xclip"
        elif command -v yum &> /dev/null; then
            echo "  sudo yum install xclip"
        elif command -v pacman &> /dev/null; then
            echo "  sudo pacman -S xclip"
        else
            echo "  xclip or xsel using your package manager"
        fi
        echo ""
    fi
fi

# Make script executable
chmod +x mypwd.py

# Create symbolic link in user's bin directory
BIN_DIR="$HOME/.local/bin"
mkdir -p "$BIN_DIR"

# Remove existing symlink if present
if [ -L "$BIN_DIR/mypwd" ] || [ -f "$BIN_DIR/mypwd" ]; then
    rm -f "$BIN_DIR/mypwd"
fi

ln -sf "$(pwd)/mypwd.py" "$BIN_DIR/mypwd"

echo "Symbolic link created: $BIN_DIR/mypwd -> $(pwd)/mypwd.py"

# Check if ~/.local/bin is in PATH
if [[ ":$PATH:" != *":$BIN_DIR:"* ]]; then
    echo ""
    echo "⚠️  $BIN_DIR is not in your PATH"
    echo ""
    
    if [ "$OS_TYPE" = "Mac" ]; then
        # Detect shell on macOS
        if [ -n "$ZSH_VERSION" ] || [ "$SHELL" = "/bin/zsh" ]; then
            SHELL_RC="$HOME/.zshrc"
        else
            SHELL_RC="$HOME/.bash_profile"
        fi
        echo "Add this line to your $SHELL_RC:"
    else
        # Linux
        if [ -n "$ZSH_VERSION" ]; then
            SHELL_RC="$HOME/.zshrc"
        else
            SHELL_RC="$HOME/.bashrc"
        fi
        echo "Add this line to your $SHELL_RC:"
    fi
    
    echo "export PATH=\"\$HOME/.local/bin:\$PATH\""
    echo ""
    echo "Then reload your shell:"
    echo "source $SHELL_RC"
    echo ""
fi

echo "✓ Installation complete!"
echo ""
echo "Usage:"
echo "  mypwd --add <tag> --username <username>         # Add password (prompted)"
echo "  mypwd --get <tag>                               # Get username only"
echo "  mypwd --get <tag> --clipboard                   # Copy password to clipboard"
echo "  mypwd --get <tag> --output       # Get password (terminal output)"
echo "  mypwd --list                     # List all tags"
echo ""

# Final checks
if [[ ":$PATH:" == *":$BIN_DIR:"* ]]; then
    echo "✓ mypwd is ready to use!"
else
    echo "⚠️  Remember to add ~/.local/bin to your PATH to use 'mypwd' command"
fi
