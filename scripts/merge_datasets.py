import os
import argparse
from scapy.all import rdpcap, wrpcap

def merge_pcap_files(input_directory, output_filename):
    pcap_files = [f for f in os.listdir(input_directory) if f.endswith('.pcap')]

    packets = []

    for pcap_file in pcap_files:
        file_path = os.path.join(input_directory, pcap_file)
        print(f"Reading packets from {file_path}")
        pcap = rdpcap(file_path)

        if packets:
            time_shift = packets[-1].time - pcap[0].time
            for pkt in pcap:
                pkt.time += time_shift

        packets.extend(pcap)

    output_path = os.path.join(input_directory, output_filename)
    print(f"Writing merged packets to {output_path}")
    wrpcap(output_path, packets)
    print("Merge complete.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Merge pcap files in a directory.')
    parser.add_argument('input_directory', help='Path to the directory containing pcap files')
    parser.add_argument('output_filename', help='Name of the output merged pcap file')
    args = parser.parse_args()
    merge_pcap_files(args.input_directory, args.output_filename)

