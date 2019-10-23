import os
import csv
##########################################################################################
class classCreateFile:
    def create_file():
        f = open("/home/san/Desktop/record.csv", "a")
        writer = csv.DictWriter(
            f, fieldnames=['ID', 'date', 'time', 'payload', 'dest_mac', 'src_mac', 'ether_type', 'version', 'IHL',
                           'ttl',
                   'proto', 'src_ip', 'dest_ip', 'icmp_type', 'code',
                   'icmp_checksum', 'tcp_src_port', 'tcp_dst_port', 'seq', 'ack', 'offset', 'reserved', 'ns_flag',
                   'cwr_flag', 'ece_flag', 'urg_flag',
                   'ack_flag', 'psh_flag', 'rst_flag', 'syn_flag', 'fin_flag', 'udp_src_port', 'udp_dst_port',
                   'udp_checksum'])
        writer.writeheader()

    def create_report_file():
        f = open("/home/san/Desktop/report.csv", "a")
        writer = csv.DictWriter(
            f,
            fieldnames=['No', 'date', 'time', 'payload', 'pattern', 'payload ID', 'pattern ID', 'n-occurrence', 'x_proto'])
        writer.writeheader()

    def create_index_mt_file():
        f = open("/home/san/Desktop/index_mt.csv", "a")
        writer = csv.DictWriter(
            f,
            fieldnames=['Index'])
        writer.writeheader()
##########################################################################################
def read_tail():
    if not os.path.exists('/home/san/Desktop/report.csv'):
        classCreateFile.create_report_file()
    if not os.path.exists('/home/san/Desktop/record.csv'):
        classCreateFile.create_file()
        id = 0
        return id
    else:
        with open('/home/san/Desktop/record.csv') as f:
            id = sum(1 for line in f) -1
            return id
##########################################################################################
def read_pattern_count():
    if not os.path.exists('/home/san/Desktop/pattern.csv'):
        return False
    else:
        with open('/home/san/Desktop/pattern.csv') as f:
            count = sum(1 for line in f)
            return count
##########################################################################################
def read_index_mt_tail():
    if not os.path.exists('/home/san/Desktop/index_mt.csv'):
        classCreateFile.create_index_mt_file()
        index_mt = 0
        return index_mt
    with open('/home/san/Desktop/index_mt.csv', 'r') as f:
        index_mt = sum(1 for line in f) -1
    return index_mt
##########################################################################################
def write_index_mt_tail(index_mt):
    csv_col = ['Index']
    dict = [{'Index': index_mt}]
    with open('/home/san/Desktop/index_mt.csv', 'a') as csvFile:
        writer = csv.DictWriter(csvFile, fieldnames=csv_col)
        # writer.writeheader()
        for data in dict:
            writer.writerow(data)

##########################################################################################

x = read_tail()
y = read_index_mt_tail()


