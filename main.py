from pyshark import LiveCapture

def capture():
    capture = LiveCapture(interface='wlp1s0', output_file='capture.pcap')
    capture.sniff(timeout=0)
    for packet in capture.sniff_continuously():
        print('packet')
        print(packet)


if __name__ == '__main__':
    capture()
