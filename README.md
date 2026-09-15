# CodeAlpha Basic Network Sniffer

A basic network packet sniffer built with Python and Scapy as part of the CodeAlpha Cyber Security Internship.

## Project Overview

This project captures and analyzes network packets passing through the local network interface.

The sniffer displays useful packet information such as:

- Source IP address
- Destination IP address
- Protocol
- Source and destination ports
- TCP flags
- Packet size
- DNS queries
- Web traffic over HTTPS and QUIC

## Features

### 1. All Traffic

Captures general IP traffic and displays information about TCP, UDP, and ICMP packets.

### 2. DNS Traffic

Monitors DNS queries and displays the domains being requested.

### 3. Web Traffic

Monitors HTTPS and QUIC traffic using TCP and UDP port 443.

### 4. Packet Counter

Each captured packet is numbered and the total number of captured packets is displayed when the capture is stopped.

## Technologies Used

- Python 3
- Scapy
- Npcap
- Windows
- VS Code

## Requirements

- Python 3.10 or later
- Npcap
- Scapy 2.7.0

## Installation

Clone the repository:

```bash
git clone https://github.com/YOUR-USERNAME/CodeAlpha_BasicNetworkSniffer.git