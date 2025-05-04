
import socket
import struct
import sys

# Format MAC address
def format_mac(mac_bytes):
    return ':'.join('%02x' % b for b in mac_bytes)

# Format IP address
def format_ip(ip_bytes):
    return '.'.join(map(str, ip_bytes))

# Ethernet frame parser
def parse_ethernet_frame(data):
    dest_mac, src_mac, proto = struct.unpack('! 6s 6s H', data[:14])
    return {
        'dest_mac': format_mac(dest_mac),
        'src_mac': format_mac(src_mac),
        'proto': socket.htons(proto),
        'payload': data[14:]
    }

# IPv4 parser
def parse_ipv4_packet(data):
    version_header_len = data[0]
    version = version_header_len >> 4
    header_len = (version_header_len & 15) * 4
    ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
    return {
        'version': version,
        'header_length': header_len,
        'ttl': ttl,
        'proto': proto,
        'src': format_ip(src),
        'target': format_ip(target),
        'payload': data[header_len:]
    }

# TCP parser
def parse_tcp_segment(data):
    src_port, dest_port, sequence, acknowledgement, offset_reserved_flags = struct.unpack('! H H L L H', data[:14])
    offset = (offset_reserved_flags >> 12) * 4
    return {
        'src_port': src_port,
        'dest_port': dest_port,
        'sequence': sequence,
        'acknowledgement': acknowledgement,
        'flags': offset_reserved_flags & 0x01FF,
        'header_length': offset,
        'payload': data[offset:]
    }

# UDP parser
def parse_udp_segment(data):
    src_port, dest_port, length = struct.unpack('! H H H', data[:6])
    return {
        'src_port': src_port,
        'dest_port': dest_port,
        'length': length,
        'payload': data[8:]
    }

# Main sniffer function
def sniff():
    try:
        conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
        print("[*] Extended Sniffer running... Press Ctrl+C to stop.")
    except PermissionError:
        print("[-] Permission denied: Run as root.")
        sys.exit(1)

    while True:
        raw_data, _ = conn.recvfrom(65535)

        eth = parse_ethernet_frame(raw_data)
        print(f"\n[Ethernet] {eth['src_mac']} -> {eth['dest_mac']} | Proto: {eth['proto']}")

        if eth['proto'] == 8:  # IPv4
            ip = parse_ipv4_packet(eth['payload'])
            print(f"  [IPv4] {ip['src']} -> {ip['target']} | Proto: {ip['proto']} | TTL: {ip['ttl']}")

            if ip['proto'] == 6:  # TCP
                tcp = parse_tcp_segment(ip['payload'])
                print(f"    [TCP] {tcp['src_port']} -> {tcp['dest_port']} | Seq: {tcp['sequence']} | Ack: {tcp['acknowledgement']} | Flags: {tcp['flags']}")

            elif ip['proto'] == 17:  # UDP
                udp = parse_udp_segment(ip['payload'])
                print(f"    [UDP] {udp['src_port']} -> {udp['dest_port']} | Length: {udp['length']}")

if __name__ == "__main__":
    sniff()
