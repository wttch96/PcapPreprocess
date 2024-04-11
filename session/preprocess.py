import json
import os
import sys
from time import time

from scapy.packet import Packet
from scapy.utils import PcapWriter
from typing_extensions import deprecated

from session.util import session_extractor


class SessionPreprocess:
    """
    session 处理工具
    """

    def __init__(self, path: str, pcap_origin_name: str):
        self.session_dict = {}
        self.session_key_index = {}
        self.session_payload_size = {}
        self.path = path
        self.pcap_origin_name = pcap_origin_name
        self.max_packet_count = 50
        # 使用保留 session 总字节最长, 即保留 session 载体的 前 2000 个字节
        self.max_session_bytes = 2000

    def can_skip(self, session_key: str = None) -> bool:
        return (session_key in self.session_payload_size
                and self.session_payload_size[session_key] >= self.max_session_bytes) and (
                session_key in self.session_dict and len(self.session_dict[session_key]) >= self.max_packet_count
        )

    def put(self, packet: Packet):
        # 提取 Session key
        session_key = session_extractor(packet)
        # 载体总长度
        if session_key not in self.session_payload_size:
            self.session_payload_size[session_key] = 0

        if self.session_payload_size[session_key] > self.max_session_bytes:
            # 已经处理的长度足够了
            if session_key in self.session_dict:
                # 保存
                self._save_session(session_key)
            # print(f"Session【{session_key}】已保存 {self.session_payload_size[session_key]} 字节载体, 跳过...")
            return

        # 如果 Session 字典里没有当前 key，就初始化
        if session_key not in self.session_dict:
            self.session_dict[session_key] = []
        # Session key 处理后保存的 pcap 文件名称
        if session_key not in self.session_key_index:
            self.session_key_index[session_key] = len(self.session_key_index)

        self.session_dict[session_key].append(packet)
        self.session_payload_size[session_key] += len(packet.payload.original)

    def index_exists(self) -> bool:
        return os.path.exists(f"{self.path}/index.json")

    def _save_session(self, session_key: str):
        pcap_file = f"{self.path}/{self.session_key_index[session_key]}.pcap"
        task_name = f"{session_key} ---> {self.pcap_origin_name}/{self.session_key_index[session_key]}.pcap"
        # print(f"开始写入文件:【{task_name}】")
        # start_time = time()
        with PcapWriter(pcap_file, append=True) as writer:
            pcap_list = self.session_dict[session_key]
            for p in pcap_list:
                writer.write(p)
            del self.session_dict[session_key]

        # print(f"写入文件完成:【{task_name}】用时:{time() - start_time:.4f}ms")

    def save(self):
        keys = [k for k in self.session_dict.keys()]
        for key in keys:
            self._save_session(key)
        with open(f"{self.path}/index.json", "w") as writer:
            json.dump(self.session_key_index, writer)
