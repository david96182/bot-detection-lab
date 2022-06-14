import time
from datetime import datetime
from multiprocessing import Process
import multiprocessing as mp
import pyshark
from settings import logger as logging

"""
Packet Analyzer for the Capture Module
 :StartTime
 :Dur
 :Proto
 :SrcAddr
 :Sport
 :Dir
 :DstAddr
 :Dport
 :State
 :sTos
 :dTos
 :TotPkts
 :TotBytes
 :SrcBytes
"""

stateDict = {'': 1, 'FSR_SA': 30, '_FSA': 296, 'FSRPA_FSA': 77, 'SPA_SA': 31, 'FSA_SRA': 1181, 'FPA_R': 46,
             'SPAC_SPA': 37, 'FPAC_FPA': 2, '_R': 1, 'FPA_FPA': 784, 'FPA_FA': 66, '_FSRPA': 1, 'URFIL': 431,
             'FRPA_PA': 5, '_RA': 2, 'SA_A': 2, 'SA_RA': 125, 'FA_FPA': 17, 'FA_RA': 14, 'PA_FPA': 48, 'URHPRO': 380,
             'FSRPA_SRA': 8, 'R_': 541, 'DCE': 5, 'SA_R': 1674, 'SA_': 4295, 'RPA_FSPA': 4, 'FA_A': 17, 'FSPA_FSPAC': 7,
             'RA_': 2230, 'FSRPA_SA': 255, 'NNS': 47, 'SRPA_FSPAC': 1, 'RPA_FPA': 42, 'FRA_R': 10, 'FSPAC_FSPA': 86,
             'RPA_R': 3, '_FPA': 5, 'SREC_SA': 1, 'URN': 339, 'URO': 6, 'URH': 3593, 'MRQ': 4, 'SR_FSA': 1,
             'SPA_SRPAC': 1, 'URP': 23598, 'RPA_A': 1, 'FRA_': 351, 'FSPA_SRA': 91, 'FSA_FSA': 26138, 'PA_': 149,
             'FSRA_FSPA': 798, 'FSPAC_FSA': 11, 'SRPA_SRPA': 176, 'SA_SA': 33, 'FSPAC_SPA': 1, 'SRA_RA': 78,
             'RPAC_PA': 1, 'FRPA_R': 1, 'SPA_SPA': 2989, 'PA_RA': 3, 'SPA_SRPA': 4185, 'RA_FA': 8, 'FSPAC_SRPA': 1,
             'SPA_FSA': 1, 'FPA_FSRPA': 3, 'SRPA_FSA': 379, 'FPA_FRA': 7, 'S_SRA': 81, 'FSA_SA': 6, 'State': 1,
             'SRA_SRA': 38, 'S_FA': 2, 'FSRPAC_SPA': 7, 'SRPA_FSPA': 35460, 'FPA_A': 1, 'FSA_FPA': 3, 'FRPA_RA': 1,
             'FSAU_SA': 1, 'FSPA_FSRPA': 10560, 'SA_FSA': 358, 'FA_FRA': 8, 'FSRPA_SPA': 2807, 'FSRPA_FSRA': 32,
             'FRA_FPA': 6, 'FSRA_FSRA': 3, 'SPAC_FSRPA': 1, 'FS_': 40, 'FSPA_FSRA': 798, 'FSAU_FSA': 13, 'A_R': 36,
             'FSRPAE_FSPA': 1, 'SA_FSRA': 4, 'PA_PAC': 3, 'FSA_FSRA': 279, 'A_A': 68, 'REQ': 892, 'FA_R': 124,
             'FSRPA_SRPA': 97, 'FSPAC_FSRA': 20, 'FRPA_RPA': 7, 'FSRA_SPA': 8, 'INT': 85813, 'FRPA_FRPA': 6,
             'SRPAC_FSPA': 4, 'SPA_SRA': 808, 'SA_SRPA': 1, 'SPA_FSPA': 2118, 'FSRAU_FSA': 2, 'RPA_PA': 171,
             '_SPA': 268, 'A_PA': 47, 'SPA_FSRA': 416, 'FSPA_FSRPAC': 2, 'PAC_PA': 5, 'SRPA_SPA': 9646,
             'SRPA_FSRA': 13, 'FPA_FRPA': 49, 'SRA_SPA': 10, 'SA_SRA': 838, 'PA_PA': 5979, 'FPA_RPA': 27,
             'SR_RA': 10, 'RED': 4579, 'CON': 2190507, 'FSRPA_FSPA': 13547, 'FSPA_FPA': 4, 'FAU_R': 2, 'ECO': 2877,
             'FRPA_FPA': 72, 'FSAU_SRA': 1, 'FRA_FA': 8, 'FSPA_FSPA': 216341, 'SEC_RA': 19, 'ECR': 3316,
             'SPAC_FSPA': 12, 'SR_A': 34, 'SEC_': 5, 'FSAU_FSRA': 3, 'FSRA_FSRPA': 11, 'SRC': 13, 'A_RPA': 1,
             'FRA_PA': 3, 'A_RPE': 1, 'RPA_FRPA': 20, '_SRA': 74, 'SRA_FSPA': 293, 'FPA_': 118, 'FSRPAC_FSRPA': 2,
             '_FA': 1, 'DNP': 1, 'FSRPA_FSRPA': 379, 'FSRA_SRA': 14, '_FRPA': 1, 'SR_': 59, 'FSPA_SPA': 517,
             'FRPA_FSPA': 1, 'PA_A': 159, 'PA_SRA': 1, 'FPA_RA': 5, 'S_': 68710, 'SA_FSRPA': 4, 'FSA_FSRPA': 1,
             'SA_SPA': 4, 'RA_A': 5, '_SRPA': 9, 'S_FRA': 156, 'FA_FRPA': 1, 'PA_R': 72, 'FSRPAEC_FSPA': 1,
             '_PA': 7, 'RA_S': 1, 'SA_FR': 2, 'RA_FPA': 6, 'RPA_': 5, '_FSPA': 2395, 'FSA_FSPA': 230, 'UNK': 2,
             'A_RA': 9, 'FRPA_': 6, 'URF': 10, 'FS_SA': 97, 'SPAC_SRPA': 8, 'S_RPA': 32, 'SRPA_SRA': 69, 'SA_RPA': 30,
             'PA_FRA': 4, 'FSRA_SA': 49, 'FSRA_FSA': 206, 'PAC_RPA': 1, 'SRA_': 18, 'FA_': 451, 'S_SA': 6917,
             'FSPA_SRPA': 427, 'TXD': 542, 'SRA_SA': 1514, 'FSPA_FA': 1, 'FPA_FSPA': 10, 'RA_PA': 3, 'SRA_FSA': 709,
             'SRPA_SPAC': 3, 'FSPAC_FSRPA': 10, 'A_': 191, 'URNPRO': 2, 'PA_RPA': 81, 'FSPAC_SRA': 1,
             'SRPA_FSRPA': 3054, 'SPA_': 1, 'FA_FA': 259, 'FSPA_SA': 75, 'SR_SRA': 1, 'FSA_': 2, 'SRPA_SA': 406,
             'SR_SA': 3119, 'FRPA_FA': 1, 'PA_FRPA': 13, 'S_R': 34, 'FSPAEC_FSPAE': 3, 'S_RA': 61105, 'FSPA_FSA': 5326,
             '_SA': 20, 'SA_FSPA': 15, 'SRPAC_SPA': 8, 'FPA_PA': 19, 'FSRPAE_FSA': 1, 'S_A': 1, 'RPA_RPA': 3,
             'NRS': 6, 'RSP': 115, 'SPA_FSRPA': 1144, 'FSRPAC_FSPA': 139}


class FlowAnalysis(Process):
    def __init__(self, name, packet):
        super().__init__(name=name)
        self.pkt_list = [packet]

        date_str = packet.frame_info.time
        date_spl = date_str.split(' ')
        date_str = date_spl[0] + ' ' + date_spl[1] + ' ' + date_spl[2] + ' ' + date_spl[3][:-3] + ' ' + date_spl[4]
        self.start_time = datetime.strptime(date_str, '%b %d, %Y %H:%M:%S.%f %Z')

        self.duration = 0

        pkt_protocol = packet.highest_layer
        if pkt_protocol == 'DATA':
            pkt_protocol = packet.layers[len(packet.layers) - 2].layer_name
        self.protocol = pkt_protocol

        if self.protocol == 'ARP':
            self.src_adr = packet.arp.src_proto_ipv4
            self.dst_adr = packet.arp.dst_proto_ipv4
            self.src_port = ''
            self.dst_port = ''
        elif 'IP' in packet:
            self.src_adr = packet.ip.src
            self.dst_adr = packet.ip.dst
        elif 'IPv6' in packet:
            self.src_adr = packet.ipv6.src
            self.dst_adr = packet.ipv6.dst

        if 'TCP' in packet:
            self.src_port = packet.tcp.srcport
            self.dst_port = packet.tcp.dstport
        elif 'ICMP' in packet:
            self.src_port = packet.icmp.udp_srcport
            self.dst_port = packet.icmp.udp_dstport
        elif 'UDP' in packet:
            self.src_port = packet.udp.srcport
            self.dst_port = packet.udp.dstport

        # self.src_adr = None
        # self.src_port = None
        # self.dst_adr = None
        # self.dst_port = None

        self.state = ''
        self.s_tos = ''
        self.d_tos = ''

        self.tot_pkts = 1
        self.tot_bytes = packet.length
        self.src_bytes = packet.length

    def run(self):
        # print(self.packet.pretty_print())
        # print(f'name: {self.name}')
        # time.sleep(5000)
        self.save_to_file()

    def flow_analysis(self, packet):
        pass

    def handle_incoming_packet(self, packet):
        self.pkt_list.append(packet)

        # check if packet ip src is self.src_adr
        # total bytes = total bytes + packet length
        # total packets = total packets + 1
        # src bytes = src bytes + packet length

        terminate = False
        if terminate:
            self.save_to_file(packet)
            self.kill()

    def save_to_file(self):
        with open('../flow_analysis.bitnetflow', 'a') as f:
            try:
                f.write(f'{self.start_time},{self.duration},{self.protocol},{self.src_adr},{self.src_port},'
                        f'{self.dst_adr},{self.dst_port},{self.state},{self.s_tos},{self.d_tos},{self.tot_pkts},'
                        f'{self.tot_bytes},{self.src_bytes}\n')
            except Exception as e:
                logging.error('Error writing to file: ' + str(e))

    def __str__(self):
        return f'{self.name: }' + str(self.start_time) + ',' + str(self.duration) + ',' + str(self.protocol) + ',' + \
               str(self.src_adr) + ',' + str(self.src_port) + ',' + str(self.dst_adr) + ',' + \
               str(self.dst_port) + ',' + str(self.state) + ',' + str(self.s_tos) + ',' + \
               str(self.d_tos) + ',' + str(self.tot_pkts) + ',' + str(self.tot_bytes) + ',' + \
               str(self.src_bytes) + '\n'
