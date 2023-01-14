from packet import FlowAnalysis
from settings import logger as logging
from pyshark import LiveCapture
from utils import get_flow_id
from iterators import TimeoutIterator


class Capture:
    """
    Class to create the network traffic capture and creates process
    for each netflow
    """

    def __init__(self, interface, output):
        """
        @param interface: name of the interface to capture traffic from
        @param output: output path where to save all captured traffic
        """
        self.interface = interface
        self.out_file = output
        self.net_flows = {}

    def start(self):
        """
        Starts the capture process and create a process for each netflow
        """
        capture = LiveCapture(self.interface, output_file=self.out_file)
        logging.info('Starting capture on interface %s', self.interface)

        packets = capture.sniff_continuously(packet_count=0)
        iterator = TimeoutIterator(packets, timeout=0.1, sentinel=None)
        repeat = True
        counter = 0
        while repeat:
            packet = next(iterator, None)

            if packet is not None:

                counter += 1
                key, inv_key = get_flow_id(packet)

                if self.net_flows.get(key) or self.net_flows.get(inv_key):
                    if self.net_flows.get(inv_key):
                        key = inv_key
                    logging.info(f'Captured packet with id: {key}')
                    netflow = self.net_flows[key]
                    netflow.handle_incoming_packet(packet)
                else:
                    logging.info(f'Captured packet with id: {key}')
                    netflow = FlowAnalysis(key, packet)
                    self.net_flows[key] = netflow

            self.update_netflows()

            # for profiling
            if counter == 10000 and len(self.net_flows) == 0:
                print('Finishing.')
                break

    def update_netflows(self):
        """
        Update the timeout of each active netflow and stop
        call save to file method from expired netflows
        """
        expired_netflows = []
        for key, value in self.net_flows.items():
            finish = False
            if value.elapsed_time > value.wait_time:
                finish = True
            else:
                value.update_elapsed_time()
                if value.elapsed_time > value.wait_time:
                    finish = True

            if finish:
                value.save_to_file()
                expired_netflows.append(key)
        for key in expired_netflows:
            self.net_flows.pop(key)