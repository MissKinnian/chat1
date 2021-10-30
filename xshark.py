"""pokus"""

from argparse import ArgumentParser
from binascii import unhexlify
from datetime import datetime

from pyshark import FileCapture


def process_pcap(filename):
    """parse and print pcap content"""

    for packet in FileCapture(filename):
        snifftime = datetime.fromtimestamp(int(float(packet.sniff_timestamp))).isoformat()

        if hasattr(packet.tcp, 'payload'):
            payload = unhexlify(packet.tcp.payload.replace(':', '')).decode()
        else:
            payload = ''

        print(
            f'{snifftime} '
            f'{packet.__repr__()} '
            f'{packet.ip.src}:{packet.tcp.srcport} {packet.ip.dst}:{packet.tcp.dstport} '
            f'{packet.tcp.flags_str} '
            f'{payload}'
        )


def main():
    """main"""

    parser = ArgumentParser()
    parser.add_argument('pcap')
    args = parser.parse_args()

    process_pcap(args.pcap)


if __name__ == '__main__':
    main()
