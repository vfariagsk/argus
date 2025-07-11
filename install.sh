#!/bin/bash

echo "Installing Argus..."

echo "Building Argus binary..."
go build -o argus ./cmd

if [ $? -ne 0 ]; then
    echo "Build failed!"
    exit 1
fi

INSTALL_DIR="/usr/local/bin"
echo "Installing to $INSTALL_DIR..."

sudo cp argus $INSTALL_DIR/

if [ $? -eq 0 ]; then
    rm argus

    echo "Argus installed successfully!"
    echo "You can now run: arm argusrgus --help"
    
    echo "Testing installation..."
    argus --help
else
    echo "Installation failed!"
    exit 1
fi 