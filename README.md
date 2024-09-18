# HTTP File Interceptor

## Overview

This Python script uses `Scapy` to sniff HTTP traffic on a specified network interface and detect requests for `.exe` files. When an `.exe` request is detected, the script modifies the server's response to redirect the download to a different file. In this case, it redirects the request to download an alternate `.exe` file from `https://www.rarlab.com/rar/wrar560.exe`.

### Features

- **Packet Sniffing**: Captures HTTP traffic (port 80) on a specified network interface.
- **Request Interception**: Detects when a user attempts to download an `.exe` file.
- **Response Manipulation**: Intercepts the server's response and replaces the download link with a specified redirect link.

## Prerequisites

- Python 3.x
- Scapy (Install via `pip install scapy`)
- Administrative or root privileges (required for sniffing and sending network packets)

## How It Works

1. **Packet Sniffing**: The script captures all TCP packets on port 80 (HTTP) on the specified network interface.
2. **EXE File Detection**: When the script detects a `.exe` file request in an HTTP packet, it logs the acknowledgment number of the request.
3. **Response Manipulation**: When the corresponding server response is intercepted, if it matches the acknowledgment number, the script modifies the packet to redirect the download.
4. **Redirect**: The response is replaced with an HTTP 301 redirect that points to `https://www.rarlab.com/rar/wrar560.exe`.

## Usage

To run the script, you need to specify the network interface on which the HTTP traffic will be intercepted.

### Command Line

```bash
sudo python3 file_interceptor.py
```

By default, the script uses the `en0` interface. You can replace it with your actual network interface if needed (e.g., `eth0` for Linux).

### How to Set the Interface

You can modify the interface variable in the code as needed:

```python
interface = "en0"  # Replace with your actual network interface
```

## Example

When the script is running, any `.exe` file request made through HTTP will be intercepted, and the user will be redirected to a new download link.

```bash
[+] EXE Request detected
[+] Replacing the file download with a redirect
```

## Script Breakdown

- **`process_packet(packet)`**:
  - Intercepts HTTP requests and responses.
  - Tracks `.exe` file requests and manipulates server responses to redirect the download to a different file.
  - Recalculates IP and TCP checksums after modifying the packet.
  
- **`start_sniffing(interface)`**:
  - Starts sniffing for TCP traffic on port 80 (HTTP).
  - Forwards each packet to `process_packet` for inspection and modification if necessary.

## Notes

- This script operates only on HTTP traffic (port 80). It does not intercept HTTPS (port 443) traffic.
- Ensure you have the correct permissions to sniff network traffic and modify packets on the network.

## Legal Disclaimer

This script is intended for educational purposes only. Unauthorized interception of network traffic may violate privacy laws and ethical guidelines. Always ensure you have proper authorization before running this script on any network.

## License

This project is licensed under the MIT License. See the LICENSE file for more information.
