import os
import sys
from time import time

# 使用 scapy.all 中导入, 否则可能 packet 读取到是 Raw 格式，无法解析
from scapy.all import Packet, PcapReader
from tqdm import tqdm

from session.preprocess import SessionPreprocess
from session.util import session_extractor

path = "/Volumes/Wttch/datasets/ISC-VPN-nonVPN-2016"
session_path = "/Volumes/Wttch/datasets/ISC-VPN-nonVPN-2016-Session"

"""
预处理 pcap 文件格式：
1. session / flow
2. all / layer
"""


class PcapPreprocess:
    def __init__(self, pcap_path: str, session_out_path: str):
        self.pcap_path = pcap_path
        self.session_out_path = session_out_path
        self.max_packet_length = 1600

    def _cut_packet(self, packet: Packet):
        length = len(packet.original)
        if length > self.max_packet_length:
            packet.original = packet.original[:self.max_packet_length]
            # print(f"切分 packet 【{packet.time}, {session_extractor(packet)}】 {1600}/{length}")

    def start(self):
        for cur_dir, sub_dirs, files in os.walk(self.pcap_path):
            rel_path = os.path.relpath(cur_dir, self.pcap_path)
            for file in files:
                if not is_pcap_file(file):
                    continue
                print(f"开始处理 {file}...")
                pcap_name = file[:file.rindex(".")]
                self._try_mk_session_pcap_path(rel_path, pcap_name)
                session_preprocess = SessionPreprocess(f"{self.session_out_path}/{rel_path}/{pcap_name}",
                                                       pcap_name)
                if session_preprocess.index_exists():
                    print(f"{file} 已经处理, 跳过!")
                    continue
                # 读取所有的 packet
                # 改用 for each 可以一个一个 packet 读取。
                sys.stdout.flush()
                x = tqdm(unit="Packet")
                with PcapReader(f"{cur_dir}/{file}") as reader:
                    for packet in reader:  # type: Packet
                        self._cut_packet(packet)
                        session_preprocess.put(packet)
                        x.update(1)
                        x.set_description_str(f"当前内存剩余{session_preprocess.total_count} Packet")
                session_preprocess.save()

    def _try_mk_session_pcap_path(self, rel_path: str, pcap_name: str):
        pcap_path = f"{self.session_out_path}/{rel_path}/{pcap_name}"
        if not os.path.exists(pcap_path):
            os.makedirs(pcap_path)
            print(f"创建文件夹 {pcap_path}")


def is_pcap_file(pcap_file: str):
    return not pcap_file.startswith(".") and (pcap_file.endswith(".pcap") or pcap_file.endswith(".pcapng"))


PcapPreprocess(path, session_path).start()
