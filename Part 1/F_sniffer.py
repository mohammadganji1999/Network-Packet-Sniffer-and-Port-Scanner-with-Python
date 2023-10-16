import socket
import struct
import textwrap
import time

class Pcap:

    def __init__(self, filename, link_type=1):
        self.pcap_file = open(filename, 'wb')
        self.pcap_file.write(struct.pack('@ I H H i I I I', 0xa1b2c3d4, 2, 4, 0, 0, 65535, link_type))

    def write(self, data):
        ts_sec, ts_usec = map(int, str(time.time()).split('.'))
        length=len(data)
        self.pcap_file.write(struct.pack('@ I I I I', ts_sec, ts_usec, length, length))
        self.pcap_file.write(data)

    def close(self):
        self.pcap_file.close()


def main():
    pcap = Pcap('capture.pcap')
    con = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))

    while True:

        raw_data, address = con.recvfrom(65536)
        pcap.write(raw_data)
        destinition_mac, Source_mac, Ethernet_proto, data = ethernet_frame(raw_data)

        print('\nEthernet Frame: ')

        print('\t - ' + "Destination: {}, Source: {}, Protocol: {}".format(destinition_mac, Source_mac,Ethernet_proto))

        if Ethernet_proto == 8:
            (version, header_length, TTL, protocol, source, target, data) = IPv4_packet(data)
            print('\t - ' + "IPv4 packet: ")
            print('\t\t- '+ "version: {}, Header Length: {}, TTL: {}".format(version, header_length, TTL))
            print('\t\t- '+ "Protocol: {}, Source: {}, Target: {}".format(protocol, source, target))
# icmp#################################################################################################################
            if protocol == 1:
                (icmp_type, code, checksum, data) = ICMP_packet(data)
                print('\t - '+ 'ICMP packet:')
                print('\t\t- '+ "Type: {}, Code: {}, Checksum: {}".format(icmp_type, code, checksum))
                print('\t\t- '+ "Data:")
                print(format_multi_line('\t\t\t ', data))

# tcp##################################################################################################################
            elif protocol == 6:
                (src_port, dest_port, sequence, acknowlegment, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn,
                 flag_fin, data) = TCP_segment(data)
                print('\t - ' + 'TCP packet:')
                print('\t\t- ' + "Source Port: {}, Destination Port: {}".format(src_port, dest_port))
                print('\t\t- ' + "Sequence: {}, Acknowlegment: {}".format(sequence, acknowlegment))
                print('\t\t- ' + "Flags:")
                print('\t\t\t - ' + "URG: {}, ACK: {}, PSH: {}, RST: {}, SYN: {}, FIN: {}".format(flag_urg, flag_ack,flag_psh, flag_rst,flag_syn, flag_fin))

# HTTP #############################################################################################################
                if src_port == 80 or dest_port == 80:
                    print('\t\t- '+ 'HTTP Data:')
                    try:
                        try:
                            data = raw_data.decode('utf-8')
                        except:
                            data = raw_data
                        http_info = str(data).split('\n')
                        for line in http_info:
                            print('\t\t\t ' + str(line))
                    except:
                        print(format_multi_line('\t\t\t ', data))
# FTP
                if dest_port == 21 or dest_port == 20:
                    print('\t\t- '+ 'FTP Data:')
                    print(format_multi_line('\t\t\t ', data))

                else:
                    print('\t\t- '+ 'TCP Data:')

                    print(format_multi_line('\t\t\t ', data))


# udp##########################################################################################################
            elif protocol == 17:
                src_port, dest_port, size, data = udp_segment(data)
                print('\t - '+ 'UDP packet:')
                print('\t\t- '+ "Source Port: {}, Destination Port: {}, Length: {}".format(src_port, dest_port, size))
# DNS###########################################################################################################
                if src_port == 53 or dest_port == 53:
                    (Total_questions, Total_answer_RRs, Total_Authority_RRs, Total_Add_RRs, Questions,
                     Ans_RRs, Authority_RRs,
                     Additional_RRs) = dns(data)
                    print('\t\t- ' + 'DNS Data:')
                    print('\t\t- ' + "Questions: {}, RRs Answers: {}, Authority RRs: {}, Additional_RRs: {}".format(
                        Questions, Ans_RRs, Authority_RRs,
                        Additional_RRs))

            elif protocol == 2054:
# ARP#########################################################################################################
                (Hardware_type, Protocol_Type, Hardware_address_length, protocol_address_length,
                 Operation, Src_mac, Src_proto_address, Dest_mac, Dest_port_addr) = arp(data)
                print('\t - ' + 'ARP packet:')
                print('\t\t- '+ "Hardware Type: {}, Protocol Type: {}, Mac Address Length: {}".format(Hardware_type, Protocol_Type,Hardware_address_length))
                print('\t\t- ' + "Source Mac Address: {}, Destination Mac Address: {}".format(Src_mac, Dest_mac))
                print('\t\t- ' + "Sender Protocol Address: {}, Destination Protocl Address: {}".format(Src_proto_address,Dest_port_addr))

            else:
                print('\t - ' + "Data: ")
                print(format_multi_line('\t\t ', data))

    pcap.close()


# Unpack ethernet frame
def ethernet_frame(data):
    Destination_addr, Src_addr, length = struct.unpack('! 6s 6s H', data[:14])
    return get_mac_addr(Destination_addr), get_mac_addr(Src_addr), socket.htons(length), data[14:]


def arp(data):
    (Hardware_type, Protocol_Type, Hardware_address_length, protocol_address_length,
            op_code, sender_hardware_addr, sender_proto_addr, target_hardware_addr, target_porto_addr, ) = struct.unpack("! H H B B H 6s 4s 6s 4s", data)

    Dest_mac = get_mac_addr(target_hardware_addr)
    Src_mac = get_mac_addr(sender_hardware_addr)

    return (Hardware_type, Protocol_Type, Hardware_address_length, protocol_address_length,
            op_code, Src_mac, sender_proto_addr, Dest_mac, target_porto_addr, )



def dns(data):
    number_of_questions, number_of_answer_RRs, number_of_Authority_RRs, number_of_Additional_RRs = struct.unpack("! H H H H",data[4:12])
    Questions, Answers_RRs, Authority_RRs, Additional_RRs = struct.unpack("! L L L L", data[12:])
    return (number_of_questions, number_of_answer_RRs, number_of_Authority_RRs, number_of_Additional_RRs, Questions, Answers_RRs, Authority_RRs,Additional_RRs)


# Return properly formatted MAC address
def get_mac_addr(bytes_address):
    bytes_string = map('{:02x}'.format, bytes_address)
    return ":".join(bytes_string).upper()


# Unpack IPv4 packet
def IPv4_packet(data):
    version_header_length = data[0]
    version = version_header_length >> 4
    header_length = (version_header_length & 15)
    TTL, protocol, src, destination = struct.unpack("! 8x B B 2x 4s 4s", data[:20])
    return version, header_length, TTL, protocol, IPv4(src), IPv4(destination), data[header_length:]


# return properly formatted IPv4 address
def IPv4(address):
    return ":".join(map(str, address))

# Unpack ICMP packet
def ICMP_packet(data):
    icmp_type, code, checksum = struct.unpack("! B B H", data[:4])
    return icmp_type, code, checksum, data[4:]


# Unpack TCP segment
def TCP_segment(data):
    (source_port, destinition_port, sequence_number, acknowlegment_number, offset_reserved_flag) = struct.unpack("! H H L L H", data[:14])
    offset = (offset_reserved_flag >> 12) * 4

    urg = (offset_reserved_flag & 32) >> 5
    ack = (offset_reserved_flag & 16) >> 4
    psh = (offset_reserved_flag & 8) >> 3
    rst = (offset_reserved_flag & 4) >> 2
    syn = (offset_reserved_flag & 2) >> 1
    fin = offset_reserved_flag & 1

    return source_port, destinition_port, sequence_number, acknowlegment_number, urg, ack, psh, rst, syn, fin, data[offset:]

def udp_segment(data):
    src_port, dest_port, size = struct.unpack("! H H 2x H", data[:8])
    return src_port, dest_port, size, data[8:]


def format_multi_line(prefix, string, size=80):
    size -= len(prefix)
    if isinstance(string, bytes):
        string = ''.join(r"\x{:02x}".format(byte) for byte in string)
        if size % 2:
            size -= 1
    return '\n'.join([prefix + line for line in textwrap.wrap(string, size)])

main()
