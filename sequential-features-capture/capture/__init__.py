from packet import FlowAnalysis
from settings import logger as logging
from pyshark import LiveCapture
from utils import get_threads_names, get_thread_by_name
from utils import get_flow_id


class Capture:
    """
    Class to create the capture and processing flow
    """

    def __init__(self, interface, output):
        self.interface = interface
        self.out_file = output
        self.net_flows = {}

    def start(self):
        """
        Starts the capture process and create the threads for each netflow
        """
        capture = LiveCapture(self.interface, output_file=self.out_file)
        logging.info('Starting capture on interface %s', self.interface)

        for packet in capture.sniff_continuously(packet_count=100):   # live capture
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
            print(self.net_flows)
