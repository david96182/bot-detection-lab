import time
from multiprocessing import Process
import multiprocessing as mp
import pyshark


class FlowAnalysis(Process):
    def __init__(self, name, packet):
        super().__init__(name=name)
        self.packet = packet
        self.pkt_list = [packet]

    def run(self):
        print(self.packet.pretty_print())
        print(self.name)
        time.sleep(5000)
        print(mp.current_process().name)

    def flow_analysis(self, packet):
        pass

    def handle_incoming_packet(self, packet):
        self.pkt_list.append(packet)
