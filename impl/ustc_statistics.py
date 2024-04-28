from typing import Any

from scapy.layers.inet import IP
from scapy.packet import Packet

from preprocessor import PcapPreprocessor, PcapPreprocessTask
from util import IPUtil


class _UstcStatisticsTask(PcapPreprocessTask):
    """
    USTC-tfc2016 数据集统计分析实际处理任务。
    """

    def __init__(self, **kwargs) -> None:
        super().__init__(**kwargs)

        self.pcap_count = 0
        self.pcap_total_length = 0
        self.pcap_payload_total_length = 0
        self.ip_type_src = {}  # type: dict[str, int]
        self.ip_type_dst = {}  # type: dict[str, int]

    def pcap_start(self) -> None:
        self.pcap_count = 0
        self.pcap_total_length = 0
        self.pcap_payload_total_length = 0
        self.ip_type_src = {}
        self.ip_type_dst = {}

    def preprocess(self, packet: Packet):
        self.pcap_count += 1
        self.pcap_total_length += len(packet.payload)
        self.pcap_payload_total_length += len(packet)

        if packet.haslayer(IP):
            ip = packet.getlayer(IP)  # type: IP
            ip_src = ip.src
            ip_dst = ip.dst

            ip_src_class: str = IPUtil.get_ip_class(ip_src)
            ip_dst_class: str = IPUtil.get_ip_class(ip_dst)

            ip_src_count: int = self.ip_type_src.get(ip_src_class, 0) + 1
            ip_dst_count: int = self.ip_type_dst.get(ip_dst_class, 0) + 1

            # 统计 ip 地址的 ABCD 分类
            self.ip_type_src[ip_src_class] = ip_src_count
            self.ip_type_dst[ip_dst_class] = ip_dst_count

    def pcap_completed(self) -> Any:
        """这些数据将保存在处理完成的 completed.json 文件里"""
        return {
            "pcap_count": self.pcap_count,
            "pcap_total_length": self.pcap_total_length,
            "pcap_payload_total_length": self.pcap_payload_total_length,
            "ip_type_src": self.ip_type_src,
            "ip_type_dst": self.ip_type_dst
        }


class UstcStatistics(PcapPreprocessor):
    """
    USTC-tfc2016 数据集统计分析。

    各个文件的包数, 整体长度, 载体长度, 每个网段的数据数量, 应用层协议数量.
    """

    def __init__(self, root_path: str, output_path: str, max_worker: int = 2) -> None:
        super().__init__(root_path, output_path, max_worker)

    def create_task(self, **kwargs) -> _UstcStatisticsTask:
        return _UstcStatisticsTask(**kwargs)
