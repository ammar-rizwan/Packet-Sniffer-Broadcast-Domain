import socket
import struct
import time 

def main():
    connection = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    while True:
    	#getting ethernet frame
        input1, address = connection.recvfrom(65536)
        dest_mac, src_mac, eprotocol, data = sniffEthernet(input1)

        print('\n Ethernet Frame: ')
        print('\t - ' + 'Destination: {}, Source: {}, Protocol: {}'.format(dest_mac, src_mac, eprotocol))

        if eprotocol == 8:
            (version, header_length, ttl, proto, src, target, data) = sniffIP(data)
            print('\t - ' + "IPV4 Packet:")
            print('\t\t - ' + 'Version: {}, Header Length: {}, TTL: {}'.format(version, header_length, ttl))
            print('\t\t\t - ' + 'protocol: {}, Source: {}, Target: {}'.format(proto, src, target))

            # if icmp 
            if proto == 1:
                icmp_type, code, checksum, data = sniffICMP(data)
                print('\t - ' + 'ICMP Packet:')
                print('\t\t - ' + 'Type: {}, Code: {}, Checksum: {},'.format(icmp_type, code, checksum))
                print('\t\t - ' + 'ICMP Data:')
                print('\t\t\t   ', data)

            # if tcp protocol
            elif proto == 6:
                start1=time.time()
                src_port, dest_port, sequence, acknowledgment, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin = struct.unpack(
            '! H H L L H H H H H H', raw_data[:24])
                print('\t - '+ 'TCP Segment:')
                print('\t\t - ' + 'Source Port: {}, Destination Port: {}'.format(src_port, dest_port))
                print('\t\t - ' + 'Sequence: {}, Acknowledgment: {}'.format(sequence, acknowledgment))
                print('\t\t - ' + 'Flags:')
                print('\t\t\t - ' + 'URG: {}, ACK: {}, PSH: {}'.format(flag_urg, flag_ack, flag_psh))
                print('\t\t\t - ' + 'RST: {}, SYN: {}, FIN:{}'.format(flag_rst, flag_syn, flag_fin))
                end1=time.time()
                print('Time to sniff '+str(end1-start1))
                print('===============================================================================')


                if len(data) > 0:
                    if src_port == 80 or dest_port == 80:
                        print('\t\t - ' + 'HTTP Data:')
                        try:
                            http = HTTP(data)
                            http_info = str(http.data).split('\n')
                            for line in http_info:
                                print('\t\t\t   '+ str(line))
                        except:
                            print('\t\t\t   ', data)
                    else:
                        print('\t\t - ' + 'TCP Data:')
                        print('\t\t\t   ', data)
            # If udp protocol
            elif proto == 17:
                start=time.time()
                src_port, dest_port, length, data = sinffUDP(data)
                print('\t - ' + 'UDP Segment:')
                print('\t\t - ' + 'Source Port: {}, Destination Port: {}, Length: {}'.format(src_port, dest_port, length))
                end=time.time()
                print('Time to sniff '+str(end-start))
                start=0
                end=0
                print('===============================================================================')
                

            # Other IPv4
            else:
                print('\t - ' + 'Other IPv4 Data:')
                print('\t\t\t   ', data)

        else:
            print('Ethernet Data:')
            print('\t   ', data)




def sniffEthernet(data):
    # 6 byte   6 byte   2 byte  
    dest_mac, src_mac, proto = struct.unpack('! 6s 6s H', data[:14])
    return get_mac_address(dest_mac), get_mac_address(src_mac), socket.htons(proto), data[14:]

def get_mac_address(bytes_address):
    bytes_str = map('{:02x}'.format, bytes_address)
    mac_address = ':'.join(bytes_str).upper()
    return mac_address

def sniffIP(data):
    version_header_len = data[0]
    version = version_header_len >> 4
    header_len = (version_header_len & 15) * 4
    ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
    return version, header_len, ttl, proto, ipv4(src), ipv4(target), data[header_len:]

def ipv4(address):
    return '.'.join(map(str, address))


def sniffICMP(data):
    icmp_type, code, checksum = struct.unpack('! B B H', data[:4])
    return icmp_type, code, checksum, data[4:]

def tcp_seg(data):
    (src_port, destination_port, sequence, acknowledgenment, offset_reserv_flag) = struct.unpack('! H H L L H', data[:14])
    #Bit shifting to get the appropriate field
    offset = (offset_reserv_flag >> 12) * 4
    flag_urg = (offset_reserved_flag & 32) >> 5
    flag_ack = (offset_reserved_flag & 32) >>4
    flag_psh = (offset_reserved_flag & 32) >> 3
    flag_rst = (offset_reserved_flag & 32) >> 2
    flag_syn = (offset_reserved_flag & 32) >> 1
    flag_fin = (offset_reserved_flag & 32) >> 1

    return src_port, dest_port, sequence, acknowledgement, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data[offset:]

def sinffUDP(data):
    src_port, dest_port, size = struct.unpack('! H H 2x H', data[:8])
    return src_port, dest_port, size, data[8:]


main()
