import queue
import time
from threading import Thread
from settings import logger as logging
from utils import get_date_string

"""
Packet Analyzer for the Capture Module
 :StartTime
 :Dur
 :Proto
 :SrcAddr
 :Sport
 :DstAddr
 :Dport
 :State
 :sTos
 :dTos
 :TotPkts
 :TotBytes
 :SrcBytes
 :Label
"""

INTERVAL = 15
FLAGS_ORDER = 'FSRPAECU'
# scapy order: FSRPAUECN


class FlowAnalysis(Thread):
    def __init__(self, name, packet, loop_time=1.0 / 60):
        super().__init__(name=name)

        self.q = queue.Queue()
        self.timeout = loop_time
        self.wait_time = INTERVAL
        self.continue_flag = True

        self.start_time = get_date_string(packet.frame_info.time)

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
            self.s_tos = packet.ip.dsfield_dscp
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

        self.state = ''
        self.state = self.calculate_network_state(packet)
        self.d_tos = ''
        if not hasattr(self, 's_stos'):
            self.s_tos = ''

        self.tot_pkts = 1
        self.tot_bytes = int(packet.length)
        self.src_bytes = int(packet.length)

        self.flow = 'Background'
        if '172.22.0' in self.src_adr or '172.22.0' in self.dst_adr:
            last_src = None
            last_dst = None
            if '172.22.0' in self.src_adr:
                last_src = int(self.src_adr.split('.')[len(self.src_adr.split('.'))-1])
            if '172.22.0' in self.dst_adr:
                last_dst = int(self.dst_adr.split('.')[len(self.dst_adr.split('.'))-1])
            if (last_src and last_src > 3) or (last_dst and last_dst > 3):
                self.flow = 'Botnet'
            elif (last_src and last_src == 1) or (last_dst and last_dst == 1):
                self.flow = 'Normal'

        logging.info(f'Packet #{packet.number} processed in thread: %s', self.name)

    def on_thread(self, function, *args, **kwargs):
        self.q.put((function, args, kwargs))

    def run(self):
        while self.continue_flag and self.wait_time > 0:
            time.sleep(1)
            self.wait_time = self.wait_time - 1
            try:
                function, args, kwargs = self.q.get(timeout=self.timeout)
                function(*args, **kwargs)
                self.wait_time = INTERVAL
            except queue.Empty:
                self.idle()
        if self.continue_flag:
            self.save_to_file()

    def idle(self):
        pass

    def interrupt_handler(self, packet):
        self.wait_time = 0

    def handle_incoming_packet(self, packet):

        inc_time = get_date_string(packet.frame_info.time)
        self.duration = (inc_time - self.start_time).total_seconds()

        self.tot_pkts += 1
        self.tot_bytes += int(packet.length)

        # check if packet ip src is self.src_adr
        if self.protocol == 'ARP':
            if self.src_adr == packet.arp.src_proto_ipv4:
                self.src_bytes += int(packet.length)
        elif 'IP' in packet:
            if self.src_adr == packet.ip.src:
                self.src_bytes += int(packet.length)
                self.s_tos = packet.ip.dsfield_dscp
            else:
                self.d_tos = packet.ip.dsfield_dscp
        elif 'IPv6' in packet:
            if self.src_adr == packet.ipv6.src:
                self.src_bytes += int(packet.length)

        self.state = self.calculate_network_state(packet)
        terminate = False
        if 'F' in self.state or 'R' in self.state:
            pass

        logging.info(f'Packet #{packet.number} processed in thread: %s', self.name)
        if terminate:
            self.save_to_file()
            self.kill()

    def calculate_network_state(self, packet):
        state = ''
        if 'UDP' in packet:
            self.state = 'CON'
        if 'TCP' in packet:
            is_src = False
            if self.src_adr == packet.ip.src:
                is_src = True
            # [flags_res', 'flags_ns', 'flags_cwr' ,'flags_ecn', 'flags_urg', 'flags_ack', 'flags_push',
            # 'flags_reset', 'flags_syn', 'flags_fin', 'flags_str'] LETTERS OF STATES: flags_cwr - C, tcp.flags_ecn -
            # E, tcp.flags_urg - U, tcp.flags_ack - A, flags_push - P 8          flags_reset - R, flags_syn - S,
            # flags_fin - F discarted tcp: tcp.flags_res ,tcp.flags_ns,
            tcp_flags = {'F': packet.tcp.flags_fin, 'S': packet.tcp.flags_syn, 'R': packet.tcp.flags_reset,
                         'P': packet.tcp.flags_push, 'A': packet.tcp.flags_ack, 'E': packet.tcp.flags_ecn,
                         'C': packet.tcp.flags_cwr, 'U': packet.tcp.flags_urg}

            if self.state == '':
                self.state = '_'
            state_split = self.state.split('_')
            if is_src:
                state_update = state_split[0]
            else:
                state_update = state_split[1]
            # iterate tcp_flags dictionary
            for key in tcp_flags.keys():
                if tcp_flags[key] == '1':
                    if key not in state_update:
                        if state_update == '':
                            state_update = key
                        else:
                            flags_before = FLAGS_ORDER[:FLAGS_ORDER.index(key)]
                            index = None
                            for flag in flags_before:
                                if flag in state_update:
                                    index = state_update.index(flag)
                            if index is not None:
                                index += 1
                                state_update = ''.join([state_update[:index], key, state_update[index:]])
                            else:
                                state_update = ''.join([key, state_update])
            if is_src:
                state = ''.join([state_update, '_', state_split[1]])
            else:
                state = ''.join([state_split[0], '_', state_update])

        if self.protocol == 'ARP':
            if packet.arp.opcode == 1:
                self.state = 'CON'
            elif packet.arp.opcode == 2:
                self.state = 'RSP'
            else:
                self.state = 'INT'
        return state

    def save_to_file(self):
        with open('flow_analysis.bitnetflow', 'a') as f:
            try:
                f.write(f'{self.start_time},{self.duration},{self.protocol},{self.src_adr},{self.src_port},'
                        f'{self.dst_adr},{self.dst_port},{self.state},{self.s_tos},{self.d_tos},{self.tot_pkts},'
                        f'{self.tot_bytes},{self.src_bytes},flow={self.flow}\n')
                logging.info('Saving to file flow with id: %s', self.name)
            except Exception as e:
                logging.error('Error writing to file: ' + str(e))
