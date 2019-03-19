import socket
import struct

def parsing_ethernet_header(data):
    # 6 * char, 6 * char, 2 byte String = 14bytes, tuple of 13 elements 
    ethernet_header = struct.unpack("!6c6c2s",data)
    ether_src = convert_ethernet_address(ethernet_header[0:6])
    ether_dest = convert_ethernet_address(ethernet_header[6:12])
    ip_header = "0x"+ethernet_header[12].hex()

    print("=====ethernet header=====")
    print("src_mac_address:",ether_src)
    print("dest_mac_address:",ether_dest)
    print("ip_version",ip_header)
    
def convert_ethernet_address(data):
    ethernet_addr = list()
    for i in data:
        ethernet_addr.append(i.hex())
    # Convert list to String
    ethernet_addr = ":".join(ethernet_addr)
    return ethernet_addr

def parsing_ip_header(data):
    global protocol, ether_end, ip_end
    
    # B 1byte unsigned int H 2byte unsigned int
    ip_header = struct.unpack("!2B3H2B1H4B4B",data)
    ip_src = convert_ip_address(data[8:12])
    ip_dest = convert_ip_address(data[12:16])
    # Get protocol to classify tcp or udp
    protocol = ip_header[6]
    # If IHL > 5 ip header has option 
    ip_end = ether_end + 4 * (ip_header[0] % 16)
    print("=====ip header=====")
    print("ip_version:",ip_header[0] // 16)
    print("ip_Length:",ip_header[0] % 16)
    print("differentiated_service_codepoint:",ip_header[1] // 4)
    print("explicit_congestion_notification:",ip_header[1] % 4)
    print("total_length:",ip_header[2])
    print("identification:",ip_header[3])
    print("flag:",hex(ip_header[4]))
    print(">>>reserved_bit:",       (ip_header[4]//(2**15))%2)
    print(">>>not_fragments:",      (ip_header[4]//(2**14))%2)
    print(">>>fragments:",          (ip_header[4]//(2**13))%2)
    print(">>>fragments_offset:",   ip_header[4]%(2**13))
    print("Time to live:",ip_header[5])
    print("protocol:",hex(ip_header[6]))
    print("header checksum:",hex(ip_header[7]))
    print("source_ip_address:",ip_src)
    print("dest_ip_address:",ip_dest)
    
def convert_ip_address(data):
    ip_addr = list()
    for i in data:
        ip_addr.append(str(i))
    # Convert list to String
    ip_addr = ".".join(ip_addr)
    return ip_addr

def parsing_tcp_header(data):
    # B 1byte unsigned int H 2byte unsigned int
    tcp_header = struct.unpack("!2H2I4H",data)
    print("=====tcp header=====")
    print("src_port:",tcp_header[0])
    print("dec_port:",tcp_header[1])
    print("seq_num:",tcp_header[2])
    print("ack_num:",tcp_header[3])
    print("header_len:",tcp_header[4] // (2**12))
    flags = tcp_header[4] % (2**12)
    print("flags:",flags)
    print(">>>reserved:",flags//(2**9))
    print(">>>nonce:",(flags//(2**8))%2)
    print(">>>cwr:",(flags//(2**7))%2)
    print(">>>ece:",(flags//(2**6))%2)
    print(">>>urgent:",(flags//(2**5))%2)
    print(">>>ack:",(flags//(2**4))%2)
    print(">>>push:",(flags//(2**3))%2)
    print(">>>reset:",(flags//(2**2))%2)
    print(">>>syn:",(flags//(2**1))%2)
    print(">>>fin:",(flags)%2)
    print("window_size:",tcp_header[5])
    print("checksum:",tcp_header[6])
    print("urgent_pointer:",tcp_header[7])
    
def parsing_udp_header(data):
    print("=====udp header=====")
    udp_header = struct.unpack("!4H",data)
    print("src_port:",udp_header[0])
    print("dst_port:",udp_header[1])
    print("leng:",udp_header[2])
    print("header checksum:",hex(udp_header[3]))
    

if __name__ == '__main__':
    recv_socket = socket.socket(socket.PF_PACKET,socket.SOCK_RAW,socket.ntohs(0x0800))
    while True:
        protocol = -1
        ether_end = 14
        ip_end = 34
        
        data = recv_socket.recvfrom(20000)
        # Minumum data is 14+20+8 else dummy
        if len(data[0]) <= 42:
            continue
        
        parsing_ethernet_header(data[0][0:ether_end])
        parsing_ip_header(data[0][ether_end:ip_end])
        # print(type(protocol))
        # print(protocol)
        if protocol == 6:
            parsing_tcp_header(data[0][ip_end:ip_end+20])
        elif protocol == 17:
            parsing_udp_header(data[0][ip_end:ip_end+8])


