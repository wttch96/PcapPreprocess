import json
from dataclasses import dataclass, field, asdict
from typing import Any

from scapy.layers.dhcp import DHCP
from scapy.layers.dhcp6 import DHCP6
from scapy.layers.dns import DNS
from scapy.layers.http import HTTP
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import ARP
from scapy.layers.llmnr import LLMNRQuery, LLMNRResponse
from scapy.layers.ntp import NTP
from scapy.layers.snmp import SNMP
from scapy.packet import Packet

from preprocessor import PcapPreprocessor, PcapPreprocessTask
from util.ip import get_ip_class


# MARK: - 统计数据类

@dataclass
class PcapCounter:
    """
    统计原始包相关的信息。

    Attributes:
        pcap (int): 原始包的个数
        total_length (int): 原始包的总长度
        payload_total_length (int): 载体的总长度
    """
    pcap: int = 0
    total_length: int = 0
    payload_total_length: int = 0

    def count(self, packet: Packet):
        self.pcap += 1
        self.total_length += len(packet)
        self.payload_total_length += len(packet.payload)


@dataclass
class SessionCounter:
    """
    统计 Session 中包的个数、原始包的数据大小、载体数据包的大小。

    Attributes:
        count (int): session 所包含的数据包的个数
        total_length (int): session 所包含的原始数据包的总长度
        payload_total_length (int): session 所包含的载体数据的总长度
    """
    count: int = 0
    total_length: int = 0
    payload_total_length: int = 0

    def statistics(self, packet: Packet) -> None:
        self.count += 1
        self.total_length += len(packet)
        self.payload_total_length += len(packet.payload)


@dataclass
class L4Counter:
    """
    传输层协议统计。

    Attributes:
        tcp (int): tcp 协议包的数量
        udp (int): udp 协议包的数量
    """
    tcp: int = 0
    udp: int = 0
    other: int = 0

    def count(self, packet: Packet):
        if packet.haslayer(TCP):
            self.tcp += 1
        elif packet.haslayer(UDP):
            self.udp += 1
        else:
            self.other += 1


@dataclass
class IPCounter:
    v4_count: int = 0
    v6_count: int = 0
    other_count: int = 0
    v4_src_class_map: dict[str, int] = field(default_factory=dict)
    v4_dst_class_map: dict[str, int] = field(default_factory=dict)
    v4_class_rel_map: dict[str, dict[str, int]] = field(default_factory=dict)

    def count(self, packet: Packet):

        if packet.haslayer(IP):
            ip: IP = packet.getlayer(IP)
            ip_src = ip.src
            ip_dst = ip.dst

            ip_src_class: str = get_ip_class(ip_src)
            ip_dst_class: str = get_ip_class(ip_dst)
            # 统计 ip v4
            self.v4_count += 1

            # 统计 IPv4 ABCDE网段
            if ip_src_class not in self.v4_src_class_map:
                self.v4_src_class_map[ip_src_class] = 0
            if ip_dst_class not in self.v4_dst_class_map:
                self.v4_dst_class_map[ip_dst_class] = 0
            self.v4_src_class_map[ip_src_class] += 1
            self.v4_dst_class_map[ip_dst_class] += 1

            # 统计 IPv4 ABCDE网段关系
            if ip_src_class not in self.v4_class_rel_map:
                self.v4_class_rel_map[ip_src_class] = {}
            if ip_dst_class not in self.v4_class_rel_map[ip_src_class]:
                self.v4_class_rel_map[ip_src_class][ip_dst_class] = 0
            self.v4_class_rel_map[ip_src_class][ip_dst_class] += 1
        elif packet.haslayer(IPv6):
            self.v6_count += 1
        else:
            self.other_count += 1


@dataclass
class Counter:
    """
    pcap 文件统计的数据类。
    
    Attributes:
        pcap (PcapCounter): 文件的里面数据包统计
        l4 (L4Counter): 传输层协议统计
        l7 (dict[str, int]): 应用层协议统计
        ip (IPCounter): ip 地址统计
    """
    pcap: PcapCounter = field(default_factory=PcapCounter)
    l4: L4Counter = field(default_factory=L4Counter)
    l7: dict[str, int] = field(default_factory=dict)
    ip: IPCounter = field(default_factory=IPCounter)

    def count(self, packet: Packet):
        self.pcap.count(packet)
        self.l4.count(packet)
        self.ip.count(packet)


class _StatisticsTask(PcapPreprocessTask):
    """
    USTC-tfc2016 数据集统计分析实际处理任务。
    """

    def __init__(self, **kwargs) -> None:
        super().__init__(**kwargs)

        self.counter = Counter()

        # 应用层协议统计
        self._l7_layers = [HTTP, DNS, DHCP, DHCP6, ARP, ICMP, LLMNRQuery, LLMNRResponse, NTP, SNMP]
        self._l7_layers_name = ["http", "dns", "dhcp", "dhcp6", "arp", "icmp", "llmnr", "llmnr", "ntp", "snmp"]
        self.l7 = {name: 0 for name in self._l7_layers_name}
        self.l7['other'] = 0

        # 统计每个 session 包含的原始包的数量
        self.session_count: dict[str: SessionCounter] = {}

    def preprocess(self, packet: Packet):
        self.counter.count(packet)

        # 处理 L7 应用层协议
        flag = False
        for layer, name in zip(self._l7_layers, self._l7_layers_name):
            if packet.haslayer(layer):
                self.l7[name] += 1
                flag = True

        if not flag:
            self.l7['other'] += 1

        # 处理 session
        # session_key = session_extractor(packet)
        # session_counter = self.session_count.get(session_key, SessionCounter())
        # session_counter.statistics(packet)
        # self.session_count[session_key] = session_counter

    def pcap_completed(self) -> Any:
        """这些数据将保存在处理完成的 completed.json 文件里"""
        return asdict(self.counter)


class PcapStatistics(PcapPreprocessor):
    """
    数据集统计分析。

    各个文件的包数, 整体长度, 载体长度, 每个网段的数据数量, 应用层协议数量.
    """

    def process_completed_file(self, file_key: str, content: dict) -> None:
        print(content)

    def completed_file_key(self, cur_dir: str, file: str) -> str:
        return file

    def __init__(self, root_path: str, output_path: str, max_worker: int = 19) -> None:
        super().__init__(root_path, output_path, max_worker)

    def create_task(self, **kwargs) -> _StatisticsTask:
        return _StatisticsTask(**kwargs)
