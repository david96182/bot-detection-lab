from multiprocessing import Process
import pyshark


class FlowAnalysis(Process):
    def __init__(self, name, packet):
        super().__init__(name)
        self.packet = packet

    def run(self):
        print(packet.pretty_print())

    def flow_analysis(self, packet):
        pass
