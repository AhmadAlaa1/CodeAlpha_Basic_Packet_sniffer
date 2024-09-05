import socket
import struct

def main():
    conn = socket.socket(socket.AF_PACKET,socket.SOCK_RAW,socket.ntohs(3))
    while True:
        raw_data, addr = conn.recvfrom(65536)
        dest_mac, src_mac, eth_proto, data = unpack_ethernet_frame(raw_data)
        print("======================================================================")
        print('\nEthernet Frame:')
        print(f'\tDestination: {dest_mac},\n\tSource: {src_mac},\n\tProtocol: {eth_proto}')

        if eth_proto == 8:
            (version, header_length, ttl, proto, src, target, data) = ipv4_packet(data)
            print('\nIPv4 Packet:')
            print('\tVersion: {}, Header Length: {}, TTL: {}'.format(version, header_length, ttl))
            print(f'\tProtocol: {proto},\n\tSource: {src},\n\tTarget: {target}')

        if proto == 1:
                icmp_type, code, checksum, data = icmp_packet(data)
                print('\tICMP Packet:')
                print(f'\tType: {icmp_type}, \n\t Code: {code},\n\t Checksum: {checksum}')

        if proto == 6:
                (src_port, dest_port, sequence, acknowledgment, data) = tcp_segment(data)
                print('\nTCP Segment:')
                print(f'\tSequence: {sequence}, \n\tAcknowledgment: {acknowledgment}')
                print(f'\tSource Port: {src_port}, \n\tDestination Port: {dest_port}')

        if proto == 17:
                src_port, dest_port, length, data = udp_segment(data)
                print('\tUDP Segment:')
                print(f'\tSource Port: {src_port},\n\tDestination Port: {dest_port},\n\tLength: {length}')
        print("======================================================================")


# Unpack the Ethernet Frame Data
def unpack_ethernet_frame(data):

    # Grab the First 14 bytes and unpack it 
    dest_mac,src_mac,proto = struct.unpack('! 6s 6s H',data[:14])

    # Function To Return the Destination and Source Mac Address and The Type of Data
    # And Return all The Data After the First 14 Bytes [Payload]
    return get_mac_addr(dest_mac),get_mac_addr(src_mac),socket.htons(proto),data[14:]

# Return Formated MAC Address (ex: AA:BB:CC:DD:EE:FF)
def get_mac_addr(bytes_addr):

    #Convert Bytes_addr to String Format
    bytes_str = map('{:02x}'.format,bytes_addr)
    
    return ':'.join(bytes_str).upper()

# Unpack the IPV4 Packet Data
def ipv4_packet(data):
    version_header_length=data[0];
    version = version_header_length >> 4
    header_length = (version_header_length & 15) * 4
    ttl,proto,src,target = struct.unpack("! 8x B B 2x 4s 4s",data[:20])
    return version,header_length,ttl,proto,ipv4(src),ipv4(target),data[header_length:]

def ipv4(addr):
    return '.'.join(map(str,addr))

# Unpack the ICMP Packet Data
def icmp_packet(data):
    type,code,checksum = struct.unpack("! B B H",data[:4])
    return type,code,checksum,data[4:]

# Unpack the TCP Segment Data
def tcp_segment(data):
    (src_port, dest_port, sequence, acknowledgment) = struct.unpack('! H H L L ', data[:12])
    return src_port, dest_port, sequence, acknowledgment, data[14:]

# Unpack the UDP Segment Data
def udp_segment(data):
    src_port, dest_port, size = struct.unpack('! H H 2x H', data[:8])
    return src_port, dest_port, size, data[8:]

main()