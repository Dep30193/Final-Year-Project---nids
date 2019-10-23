# https://docs.python.org/2/library/struct.html
tab = "\t"
import socket
import struct
import textwrap                                 # connect() is not supported on packet sockets
import csv
import datetime
import os
import sys

log_data = ''
cdate, ctime = 0, 0
npa0, npa1 = '', ''     # null passed arguments
##############################################################################
import caller
pattern_bool = caller.read_pattern_count()
if pattern_bool is False:
    print('No pattern file located::')
id = caller.x   # read_tail()
print('id : {}'.format(id))
index_mt = caller.y     # read_index_mt_tail()
print('index_mt : {}'.format(index_mt))
##############################################################################
def unpackEtherFrame(data):       # unpack etherFrame, data=pkt
    # refer line 1:: ! is standardizing big/small endian
    dest_mac, src_mac, ether_type = struct.unpack('! 6s 6s H', data[:14])   # 6B+6B+2B
    return get_mac_addr(dest_mac), get_mac_addr(src_mac), socket.htons(ether_type), data[14:]
    #  htons make it a compatible format, avoid big/small endian conflict
#----------------------------------------------------------------------------------------#
def get_mac_addr(bytes_addr):       # ret properly displayed mac address
    # AA:BB:CC:DD:EE:FF
    bytes_str = map('{:02x}'.format, bytes_addr)  #map --> format with ',' instead of ()
    mac_addr = ':'.join(bytes_str).upper()
    return mac_addr
######################################################d###########################
def unpack_IP(data):
    version_and_IHL = data[0]  # take first 1 byte(8bits) then bit wise shifting right 4bit -> | 0000 version |
    version = version_and_IHL >> 4
    IHL = (version_and_IHL & 15) *4
    ttl, proto, src_ip, dest_ip = struct.unpack("! 8x B B 2x 4s 4s", data[:IHL])  #or data[:20}
    return version, IHL, ttl, proto, ipv4_format(src_ip), ipv4_format(dest_ip), data[IHL:]
#-------------------------------------------------------------------------------------#
def ipv4_format(byte_addr):
    # 192.168.43.1
    addr = '.'.join(map(str, byte_addr))
    return addr
##############################################################################
def main():     # AF_PACKET used as impl'ing own protocol, AF_INET is apply predefined tcp/udp protocol
                # SOCK_RAW conserve up to link layer headers
    global log_data
    global id
    global x_proto
    global cdate
    global ctime
    global index_mt

    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))  # ntohs - compatible for all devices
    while True:
        data, addr = conn.recvfrom(65536)  # source addr & data, 65536= max buffer size
        cdate, ctime = classTime.reveal_time(npa0,npa1)
        print('\nTimestamp : {0}  {1}'.format(cdate, ctime))


        dest_mac, src_mac, ether_type, data = unpackEtherFrame(data)
        # {ether_type}:
            # 0x0800 = IPv4
            # 0x0806 = ARP
            # 0x86DD = IPv6
        print('\nEthernet Frame: ')
        print('\tdestination: {} | source: {} | ethernet type : {} |'.format(dest_mac, src_mac, ether_type))
        # unpack ip layer
        if ether_type == 8:
            try:
                version, IHL, ttl, proto, src_ip, dest_ip, data = unpack_IP(data)
                x_proto = proto

            except Exception as e:
                print(e)
                continue

            ipv4_display(version, IHL, ttl, proto, src_ip, dest_ip)
            if proto == 1:     # 1,6,17 = icmp,tcp,udp

                id += 1

                icmp_type, code, icmp_checksum, data = unpack_ICMP(data)
                icmp_display(icmp_type, code, icmp_checksum)

                data_display = format_readable_longline("\t\t", data)
                data = format_logable_longline("", data)

                import csvIntoDict
                import compare
                pattern_list = csvIntoDict.extract_pattern()
                remap_pattern_list = PatternMatching.remap_list_without_bracket(pattern_list)
                PatternMatching.looper(data, remap_pattern_list)

                InsertDict.insert_icmp_csv(data, dest_mac, src_mac, ether_type, version, IHL, ttl, proto, src_ip,
                                           dest_ip, icmp_type, code, icmp_checksum)
                print('ID ::{}'.format(id))
                print("\tPayload: ")
                print(data_display)
                print("----------------------------------------------------------------------------")

            elif proto == 6:

                id += 1

                tcp_src_port, tcp_dst_port, seq, ack, offset, reserved, ns_flag, cwr_flag, ece_flag, urg_flag, \
                ack_flag, psh_flag, rst_flag, syn_flag, fin_flag, data = unpack_TCP(data)
                tcp_display(tcp_src_port, tcp_dst_port, seq, ack, offset, reserved, ns_flag, cwr_flag, ece_flag,
                            urg_flag, ack_flag, psh_flag, rst_flag, syn_flag, fin_flag)

                data_display = format_readable_longline("\t\t", data)
                data = format_logable_longline("", data)

                import csvIntoDict
                import compare
                pattern_list = csvIntoDict.extract_pattern()
                remap_pattern_list = PatternMatching.remap_list_without_bracket(pattern_list)
                PatternMatching.looper(data, remap_pattern_list)

                InsertDict.insert_tcp_csv(data, dest_mac, src_mac, ether_type, version, IHL, ttl, proto, src_ip,
                                           dest_ip, tcp_src_port, tcp_dst_port, seq, ack, offset, reserved, ns_flag,
                                          cwr_flag, ece_flag, urg_flag, ack_flag, psh_flag,rst_flag, syn_flag,fin_flag)
                print('ID ::{}'.format(id))
                print("\tPayload: ")
                print(data_display)
                print("----------------------------------------------------------------------------")

            elif proto == 17:

                id += 1

                udp_src_port, udp_dst_port, udp_checksum, data = unpack_UDP(data)
                udp_display(udp_src_port, udp_dst_port, udp_checksum)

                data_display = format_readable_longline("\t\t", data)
                data = format_logable_longline("", data)

                import csvIntoDict
                import compare
                pattern_list = csvIntoDict.extract_pattern()
                remap_pattern_list = PatternMatching.remap_list_without_bracket(pattern_list)
                PatternMatching.looper(data, remap_pattern_list)

                InsertDict.insert_udp_csv(data, dest_mac, src_mac, ether_type, version, IHL, ttl, proto, src_ip,
                                           dest_ip, udp_src_port, udp_dst_port, udp_checksum)
                print('ID ::{}'.format(id))
                print("\tPayload: ")
                print(data_display)
                print("----------------------------------------------------------------------------")
################################################################################################################################
class PatternMatching:
    def remap_list_without_bracket(pattern_list):
        count = caller.read_pattern_count()
        remap_pattern_list = []
        i = 0
        while count != 0:
            x = ''.join(map(str, pattern_list[i]))
            remap_pattern_list.append(x)
            i += 1
            count = count - 1
        return remap_pattern_list
#--------------------------------------------------------------------------------------------------------------------#
    def looper(data, pattern_list):
        import compare
        global index_mt
        x = 0
        count = 0
        i = -1
        mpl = []        # mpl = matched_pattern_list
        iemp = []       # imp = index_each_matched_pattern
        occ = []        # how many occurrence in each pair
        while True:
            i += 1
            try:
                pattern = pattern_list[i]
                x = compare.pass_main(pattern, data)
                if x > 0:  # x = each data-pattern paired-occurrence
                    mpl.append(pattern)     # matched pattern
                    iemp.append(i+1)        # which pattern is matched
                    occ.append(x)           # how many occurrence in each pair
                    count += 1
                continue
            except:
                break
        print('total n-match pattern: {}'.format(count))
        if count > 0:
            index_mt += 1
            caller.write_index_mt_tail(index_mt)
            PatternMatching.insert_report_csv(count, mpl, iemp, data, occ)
#--------------------------------------------------------------------------------------------------------------------#
    def insert_report_csv(count, mpl, iemp, payload, occ):
        global id
        global index_mt
        global cdate
        global ctime
        global x_proto
        # index_mt only increment if count == 0
        # iemp = index_each_matched_pattern
        # mpl  = matched_pattern_list
        # occ  = how many time the pattern appear within payload

        csv_col = ['No', 'date', 'time', 'payload', 'pattern', 'payload ID', 'pattern ID', 'n-occurrence', 'proto']
        #----------------------------------------------------------------------------------------------------------#
        while_iterate = 0
        while True:
            while_iterate += 1
            try:
                # first iterate
                if while_iterate == 1:                      # iemp [1, 2, 3]
                    dict = [{'No': index_mt, 'date': cdate, 'time': ctime, 'payload': payload, 'pattern': mpl[0],
                             'payload ID': id, 'pattern ID': iemp[0], 'n-occurrence': occ[0], 'proto': x_proto}]
                    with open('/home/san/Desktop/report.csv', 'a') as csvFile:
                        writer = csv.DictWriter(csvFile, fieldnames=csv_col)
                        # writer.writeheader()
                        for data in dict:
                            writer.writerow(data)
                # subsequent iterate
                else:
                    for i in range(count-1):
                        dict = [{'No': ' ', 'date': ' ', 'time': ' ', 'payload': payload, 'pattern': mpl[i+1],
                                 'payload ID': id, 'pattern ID': iemp[i+1], 'n-occurrence': occ[i+1], 'proto': ' '}]
                        with open('/home/san/Desktop/report.csv', 'a') as csvFile:
                            writer = csv.DictWriter(csvFile, fieldnames=csv_col)
                            # writer.writeheader()
                            for data in dict:
                                writer.writerow(data)
                    break
            except Exception as e:
                print('error on filing report.csv')
                print(e)
                break
        #----------------------------------------------------------------------------------------------------------#
################################################################################################################################
def format_readable_longline(prefix, string, width=90):
    width -= len(prefix)  # isOptional, only easier for width avoid adjustment, straightly refer to argu( = width
    if isinstance(string, bytes):
        string = ' '.join(r'\x{:02x}'.format(byte) for byte in string)
   # if not width % 2: # if odd width, return 1 == True, -1 become even
        #width -= 1
    return '\n'.join([prefix + line for line in textwrap.wrap(string, width)])

def format_logable_longline(prefix, string):
    global log_data
    if isinstance(string, bytes):
        string = ''.join(r'{:02x}'.format(byte) for byte in string)
        log_data = string
    return log_data

class classTime:
    def reveal_time(x,y):
        global micro_sec
        current = datetime.datetime.now()
        cdate = current.strftime('%Y/%m/%d')

        # micro_sec = str(current.microsecond())
        # micro_sec = current.microsecond()
        ctime = current.strftime('%H:%M:%S:%f')

        return cdate, ctime
#################################################################################################################################
class InsertDict:
    def insert_icmp_csv(payload, dest_mac, src_mac, ether_type, version, IHL, ttl, proto, src_ip, dest_ip, icmp_type,
                        code, icmp_checksum):
        global id
        global cdate
        global ctime
        x = 'NULL'
        if len(payload) == 0:
            payload = "NULL"

        csv_col = ['ID', 'date', 'time', 'payload', 'dest_mac', 'src_mac','ether_type','version','IHL','ttl','proto',
                   'src_ip','dest_ip','icmp_type','code',
                   'icmp_checksum','tcp_src_port','tcp_dst_port','seq','ack','offset','reserved','ns_flag','cwr_flag',
                   'ece_flag','urg_flag',
                   'ack_flag','psh_flag','rst_flag','syn_flag','fin_flag','udp_src_port','udp_dst_port','udp_checksum']
        if proto == 1:
            dict = [{'ID': id, 'date': cdate, 'time': ctime, 'payload': payload, 'dest_mac': dest_mac,
                     'src_mac': src_mac, 'ether_type': ether_type,
                     'version': version, 'IHL': IHL, 'ttl': ttl, 'proto': proto, 'src_ip': src_ip, 'dest_ip': dest_ip,
                     'icmp_type': icmp_type, 'code': code, 'icmp_checksum': icmp_checksum, 'tcp_src_port': 'NULL',
                     'tcp_dst_port': 'NULL', 'seq': 'NULL',
                     'ack': 'NULL', 'offset': 'NULL', 'reserved': 'NULL', 'ns_flag': 'NULL', 'cwr_flag': 'NULL',
                     'ece_flag': 'NULL',
                     'urg_flag': 'NULL', 'ack_flag': 'NULL',
                     'psh_flag': 'NULL', 'rst_flag': 'NULL', 'syn_flag': 'NULL', 'fin_flag': 'NULL',
                     'udp_src_port': 'NULL',
                     'udp_dst_port': 'NULL', 'udp_checksum': 'NULL'
                     }]

        try:
            with open('/home/san/Desktop/record.csv', 'a') as csvFile:
                writer = csv.DictWriter(csvFile, fieldnames=csv_col)
                # writer.writeheader()
                for data in dict:
                    writer.writerow(data)
        except IOError:
            print('IO error . . ')
    ##############################################################################################################################
    def insert_tcp_csv(payload, dest_mac, src_mac, ether_type, version, IHL, ttl, proto, src_ip,
                                  dest_ip, tcp_src_port, tcp_dst_port, seq, ack, offset, reserved, ns_flag, cwr_flag,
                                  ece_flag, urg_flag, ack_flag, psh_flag, rst_flag, syn_flag, fin_flag):
        global id
        global cdate
        global ctime
        x = 'NULL'

        if len(payload) == 0:
            payload = "NULL"
        csv_col = ['ID', 'date', 'time', 'payload', 'dest_mac', 'src_mac', 'ether_type', 'version', 'IHL', 'ttl',
                   'proto', 'src_ip',
                   'dest_ip', 'icmp_type', 'code', 'icmp_checksum', 'tcp_src_port', 'tcp_dst_port', 'seq', 'ack',
                   'offset', 'reserved', 'ns_flag', 'cwr_flag', 'ece_flag', 'urg_flag', 'ack_flag', 'psh_flag',
                   'rst_flag', 'syn_flag', 'fin_flag', 'udp_src_port', 'udp_dst_port', 'udp_checksum']
        if proto == 6:
            dict = [{'ID': id, 'date': cdate, 'time': ctime, 'payload': payload, 'dest_mac': dest_mac,
                     'src_mac': src_mac, 'ether_type': ether_type,
                     'version': version, 'IHL': IHL, 'ttl': ttl, 'proto': proto, 'src_ip': src_ip, 'dest_ip': dest_ip,
                     'icmp_type': 'NULL', 'code': 'NULL', 'icmp_checksum': 'NULL', 'tcp_src_port': tcp_src_port,
                     'tcp_dst_port': tcp_dst_port, 'seq': seq,
                     'ack': ack, 'offset': offset, 'reserved': reserved, 'ns_flag': ns_flag, 'cwr_flag': cwr_flag,
                     'ece_flag': ece_flag,
                     'urg_flag': urg_flag, 'ack_flag': ack_flag,
                     'psh_flag': psh_flag, 'rst_flag': rst_flag, 'syn_flag': syn_flag, 'fin_flag': fin_flag,
                     'udp_src_port': 'NULL',
                     'udp_dst_port': 'NULL', 'udp_checksum': 'NULL'
                     }]

        try:
            with open('/home/san/Desktop/record.csv', 'a') as csvFile:
                writer = csv.DictWriter(csvFile, fieldnames=csv_col)
                # writer.writeheader()
                for data in dict:
                    writer.writerow(data)
        except IOError:
            print('IO error . . ')
    ##############################################################################################################################
    def insert_udp_csv(payload, dest_mac, src_mac, ether_type, version, IHL, ttl, proto, src_ip,
                       dest_ip, udp_src_port, udp_dst_port, udp_checksum):
        global id
        global cdate
        global ctime

        x = 'NULL'
        if len(payload) == 0:
            payload = "NULL"
        csv_col = ['ID', 'date', 'time', 'payload', 'dest_mac', 'src_mac', 'ether_type', 'version', 'IHL', 'ttl',
                   'proto', 'src_ip',
                   'dest_ip', 'icmp_type', 'code', 'icmp_checksum', 'tcp_src_port', 'tcp_dst_port', 'seq', 'ack',
                   'offset', 'reserved', 'ns_flag', 'cwr_flag', 'ece_flag', 'urg_flag', 'ack_flag', 'psh_flag',
                   'rst_flag', 'syn_flag', 'fin_flag', 'udp_src_port', 'udp_dst_port', 'udp_checksum']
        if proto == 17:
            dict = [{'ID': id, 'date': cdate, 'time': ctime, 'payload': payload, 'dest_mac': dest_mac,
                     'src_mac': src_mac, 'ether_type': ether_type,
                     'version': version, 'IHL': IHL, 'ttl': ttl, 'proto': proto, 'src_ip': src_ip, 'dest_ip': dest_ip,
                     'icmp_type': 'NULL', 'code': 'NULL', 'icmp_checksum': 'NULL', 'tcp_src_port': 'NULL',
                     'tcp_dst_port': 'NULL', 'seq': 'NULL',
                     'ack': 'NULL', 'offset': 'NULL', 'reserved': 'NULL', 'ns_flag': 'NULL', 'cwr_flag': 'NULL',
                     'ece_flag': 'NULL',
                     'urg_flag': 'NULL', 'ack_flag': 'NULL',
                     'psh_flag': 'NULL', 'rst_flag': 'NULL', 'syn_flag': 'NULL', 'fin_flag': 'NULL',
                     'udp_src_port': udp_src_port,
                     'udp_dst_port': udp_dst_port, 'udp_checksum': udp_checksum
                     }]
        try:
            with open('/home/san/Desktop/record.csv', 'a') as csvFile:
                writer = csv.DictWriter(csvFile, fieldnames=csv_col)
                # writer.writeheader()
                for data in dict:
                    writer.writerow(data)
        except IOError:
            print('IO error . . ')

####################################################################################################################
def ipv4_display(version, IHL, ttl, proto, src_ip, dest_ip):
    print("\n\tIP Packet : ")
    print("\t\tversion: {0} | header_length : {1} | ttl: {2} |".format(version, IHL, ttl))
    print("\t\tprotocol : {0} | src_IP : {1} | dst_IP : {2} |".format(proto, src_ip, dest_ip))
def icmp_display(icmp_type, code, icmp_checksum):
    print("\n\tICMP Packet : ")
    print("\t\ticmp_type : {0} | code : {1} | icmp_checksum : {2} |".format(icmp_type, code, icmp_checksum))
def tcp_display(tcp_src_port, tcp_dst_port, seq, ack, offset, reserved, ns_flag, cwr_flag, ece_flag, urg_flag,
                ack_flag, psh_flag, rst_flag, syn_flag, fin_flag):
    print("\n\tTCP Segment :")
    print("\t\ttcp_src_port : {0} | tcp_dst_port : {1} | seq: {2} | ack: {3} | offset: {4} | reserved: {5} |".
          format(tcp_src_port, tcp_dst_port,seq,ack,offset,reserved))
    print("\t\tns_flag: {0} | cwr_flag: {1} | ece_flag: {2} | urg_flag: {3} |"
          .format(ns_flag,cwr_flag,ece_flag,urg_flag))
    print("\t\tack_flag: {0} | psh_flag: {1} | rst_flag: {2} | syn_flag: {3} | fin_flag: {4} | "
          .format(ack_flag,psh_flag,rst_flag,syn_flag,fin_flag))
def udp_display(udp_src_port, udp_dst_port, udp_checksum):
    print("\n\tUDP Datagram:")
    print("\t\tudp_src_port: {0} | udp_dst_port: {1} | udp_checksum: {2} |"
          .format(udp_src_port,udp_dst_port,udp_checksum))
####################################################################################################################
def unpack_ICMP(data):
    icmp_type, code, icmp_checksum = struct.unpack("! B B H",data[:4])
    return icmp_type, code, icmp_checksum, data[4:]
def unpack_TCP(data):
    tcp_src_port, tcp_dst_port, seq, ack, offset_reserved_flags = struct.unpack("! H H L L H", data[:14])
    offset = (offset_reserved_flags >> 12)*4
    reserved = (offset_reserved_flags & 3584) >> 9
    ns_flag = (offset_reserved_flags & 256) >> 8
    cwr_flag = (offset_reserved_flags & 128) >> 7
    ece_flag = (offset_reserved_flags & 64) >> 6
    urg_flag = (offset_reserved_flags & 32) >> 5
    ack_flag = (offset_reserved_flags & 16) >> 4
    psh_flag = (offset_reserved_flags & 8) >> 3
    rst_flag = (offset_reserved_flags & 4) >> 2
    syn_flag = (offset_reserved_flags & 2) >> 1
    fin_flag = (offset_reserved_flags & 1)
    return tcp_src_port, tcp_dst_port, seq, ack, offset, reserved, ns_flag, cwr_flag, ece_flag, urg_flag,\
           ack_flag, psh_flag, rst_flag, syn_flag, fin_flag, data[offset:]
def unpack_UDP(data):
    udp_src_port, udp_dst_port, udp_checksum = struct.unpack("! H H 2x H", data[:8])
    return udp_src_port, udp_dst_port, udp_checksum, data[8:]
####################################################################################################################scap
main()



