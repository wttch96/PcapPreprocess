import json
import os
from time import time

from scapy.packet import Packet
from scapy.utils import PcapWriter

from session.util import session_extractor


class SessionPreprocess:
    """
    session 处理工具
    """

    def __init__(self, path: str, pcap_origin_name: str):
        self.session_dict = {}
        self.session_key_index = {}
        self.key_list = []
        self.path = path
        self.pcap_origin_name = pcap_origin_name
        self.total_count = 0

    def save_old_session_key(self, rate=0.5):
        """
        保存 session_key 列表里最早的一部分数据到文件去。
        :param rate: 保存的比例
        """
        if self.total_count < 10000:
            return

        save_keys = [k for k in self.key_list]

        for key in save_keys:
            self._save_session(key)

    def put(self, packet: Packet):
        self.total_count += 1
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

        # 尝试进行保存, 如果内部保存的数据太多，就从最早未使用的 50% key 的数据写入文件
        self.save_old_session_key(rate=0.8)

    def index_exists(self) -> bool:
        return os.path.exists(f"{self.path}/index.json")

    def _save_session(self, session_key: str, save_all: bool = False):
        pcap_file = f"{self.path}/{self.session_key_index[session_key]}.pcap"
        task_name = f"{session_key} ---> {self.pcap_origin_name}/{self.session_key_index[session_key]}.pcap"
        print(f"开始{'' if save_all else '预'}写入文件:【{task_name}】")
        start_time = time()
        with PcapWriter(pcap_file, append=True) as writer:
            pcap_list = self.session_dict[session_key]
            self.total_count -= len(pcap_list)
            for p in pcap_list:
                writer.write(p)
            self.session_dict[session_key] = []

        print(f"{'' if save_all else '预'}写入文件完成:【{task_name}】用时:{time() - start_time:.4f}ms")

    def save(self):
        keys = [k for k in self.session_dict.keys()]
        for key in keys:
            self._save_session(key, save_all=True)
        with open(f"{self.path}/index.json", "w") as writer:
            json.dump(self.session_key_index, writer)
