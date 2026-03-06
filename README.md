# Network Discovery Tool

A Python-based network discovery tool using Scapy to identify devices on a local network.

## Features

- Discover devices on a network using ARP scanning
- Display IP address and MAC address
- Basic vendor detection based on MAC OUI

## Requirements

- Python 3
- Scapy

Install dependencies:

pip install -r requirements.txt

## Usage

Run the script with root privileges:

sudo ./venv/bin/python discovery.py

Then enter your network range when prompted.

Example:

10.0.0.0/24

## Example Output

IP Address        MAC Address         Vendor
------------------------------------------------------------
10.0.0.1          f8:79:0a:25:55:9e   Arris
10.0.0.57         bc:09:1b:5f:87:91   Apple
