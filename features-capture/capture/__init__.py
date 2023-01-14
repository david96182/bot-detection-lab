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

    def start(self):
        """
        Starts the capture process and create the threads for each netflow
        """
        capture = LiveCapture(self.interface, output_file=self.out_file)
        # capture.sniff(timeout=0)
        logging.info('Starting capture on interface %s', self.interface)

        for packet in capture.sniff_continuously(packet_count=0):   # live capture
            key, inv_key = get_flow_id(packet)

            if key in get_threads_names() or inv_key in get_threads_names():
                if inv_key in get_threads_names():
                    key = inv_key
                logging.info(f'Captured packet with id: {key}')
                thread = get_thread_by_name(key)
                thread.on_thread(thread.handle_incoming_packet, packet)
            else:
                logging.info(f'Captured packet with id: {key}')
                thread = FlowAnalysis(key, packet)
                thread.start()
