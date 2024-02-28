import json
import os

from scapy.layers.inet import IP
from scapy.layers.l2 import Ether
from scapy.packet import Packet
from scapy.utils import rdpcap, wrpcap, PcapReader, PcapWriter
from tqdm import tqdm
from session import session_extractor

path = "/Volumes/Wttch/datasets/ISC-VPN-nonVPN-2016"
session_path = "/Volumes/Wttch/datasets/ISC-VPN-nonVPN-2016-Session"

"""
预处理 pcap 文件格式：
1. session / flow
2. all / layer
"""


class SessionPreprocess:
    def __init__(self, path: str):
        self.session_dict = {}
        self.session_key_index = {}
        self.key_list = []
        self.path = path

    def put(self, packet: Packet):
        session_key = session_extractor(packet)
        if session_key not in self.session_dict:
            self.session_dict[session_key] = []

        if session_key not in self.session_key_index:
            self.session_key_index[session_key] = len(self.session_key_index)

        self.session_dict[session_key].append(packet)
        # 本次处理的 packet 的 session 放入最后面
        if session_key in self.key_list:
            self.key_list.remove(session_key)
        self.key_list.append(session_key)

        if len(self.session_dict) > 200:
            # 如果长度超标
            # 最久未使用的 session 写入文件，即第一个 session
            # 使用 append 模式
            save_key = self.key_list.pop(0)
            with PcapWriter(f"{self.path}/{self.session_key_index[session_key]}.pcap", append=True) as writer:
                pcap_list = self.session_dict.pop(save_key)
                for p in pcap_list:
                    writer.write(p)
            print(f"预写入文件{self.path}/{self.session_key_index[session_key]}.pcap")

    def index_exists(self) -> bool:
        return os.path.exists(f"{self.path}/index.json")

    def save(self):
        for key, packets in self.session_dict.items():
            with PcapWriter(f"{self.path}/{self.session_key_index[key]}.pcap", append=True) as writer:
                for packet in packets:
                    writer.write(packet)
            print(f"写入文件{self.path}/{self.session_key_index[key]}.pcap")
        with open(f"{self.path}/index.json", "w") as writer:
            json.dump(self.session_key_index, writer)


class PcapPreprocess:
    def __init__(self, pcap_path: str, session_out_path: str):
        self.pcap_path = pcap_path
        self.session_out_path = session_out_path
        self.max_packet_length = 1600

    def _cut_packet(self, packet: Packet):
        l = len(packet.original)
        if len(packet.original) > self.max_packet_length:
            packet.original = packet.original[:self.max_packet_length]
            print(f"切分 packet {1600}/{l}")

    def start(self):
        for cur_dir, sub_dirs, files in os.walk(self.pcap_path):
            rel_path = os.path.relpath(cur_dir, self.pcap_path)
            for file in files:
                if not is_pcap_file(file):
                    continue
                print(f"开始处理 {rel_path}/{file}...")
                pcap_name = file[:file.rindex(".")]
                self._try_mk_session_pcap_path(rel_path, pcap_name)
                session_preprocess = SessionPreprocess(f"{self.session_out_path}/{rel_path}/{pcap_name}")
                if session_preprocess.index_exists():
                    print(f"{file} 已经处理, 跳过!")
                    continue
                # 读取所有的 packet
                # 改用 for each 可以一个一个 packet 读取。
                i = 0
                with PcapReader(f"{cur_dir}/{file}") as reader:
                    for packet in reader:  # type: Packet
                        self._cut_packet(packet)
                        session_preprocess.put(packet)
                session_preprocess.save()
                #
                # ret = {}
                # tqdm_data = tqdm(pcap.sessions(session_extractor).items(),
                #                  bar_format="{n_fmt}/{total_fmt}|{bar}|{percentage:3.0f}%［{elapsed}<{remaining},{rate_fmt}{postfix}]{desc}")
                # for i, (key, session) in enumerate(tqdm_data):
                #     session_file = f"{self.session_out_path}/{rel_path}/{pcap_name}/{i}.pcap"
                #     wrpcap(session_file, session)
                #     tqdm_data.set_description_str(key)
                #     ret[key] = f"{i}.pcap"
                # with open(f"{self.session_out_path}/{rel_path}/{pcap_name}/pcap.json", "w") as f:
                #     json.dump(ret, f)
                #     print(f"已写入: {self.session_out_path}/{rel_path}/{pcap_name}/pcap.json")

    def _try_mk_session_pcap_path(self, rel_path: str, pcap_name: str):
        pcap_path = f"{self.session_out_path}/{rel_path}/{pcap_name}"
        if not os.path.exists(pcap_path):
            os.makedirs(pcap_path)
            print(f"创建文件夹 {pcap_path}")

    def _pcap_split(self, rel_path: str, pcap_name: str) -> bool:
        """
        判断 pcap 是否已经拆分。
        就是看里面是否有 pcap.json 这个文件。
        这个文件包含了 session_key: 文件名的一个映射。
        :param rel_path: 正在处理的文件，相对数据集根目录的路径
        :param pcap_name: 要判断的 pcap 文件名，即 `rel_path` 下的 `pcap_name` 这个文件是否已经拆分。
        :return: 已拆分返回 True, 否则 False
        """
        pcap_path = f"{self.session_out_path}/{rel_path}/{pcap_name}/pcap.json"
        if os.path.exists(pcap_path):
            print(f"{rel_path}/{pcap_name} 已经拆分!")
            return True
        return False


def is_pcap_file(pcap_file: str):
    return not pcap_file.startswith(".") and (pcap_file.endswith(".pcap") or pcap_file.endswith(".pcapng"))


PcapPreprocess(path, session_path).start()
