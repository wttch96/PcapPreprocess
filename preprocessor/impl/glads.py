import os.path
import pickle
from collections import OrderedDict
from typing import Optional, Any

import numpy as np
from scapy.packet import Packet, Raw
from scapy.layers.inet import IP, UDP, TCP
from scapy.layers.dns import DNS
from scapy.layers.dhcp import DHCP
from scapy.layers.dhcp6 import DHCP6
from scapy.layers.ntp import NTP
from scapy.layers.snmp import SNMP
from scapy.layers.llmnr import LLMNRQuery, LLMNRResponse

from preprocessor.session import SessionPreprocessTask
from preprocessor import PcapPreprocessor
from wth.log import get_logger


class _GladsSessionData:
    def __init__(self):
        self.hdr_list = []
        self.pay_list = []
        self.last_arrival_time = None
        self.server_ip = None
        self.pay_count = 0


# GLADS: 论文的预处理任务
def _extract_hdr(inter_arrival_time: int, direction: bool,
                 tcp: Optional[TCP] = None, udp: Optional[UDP] = None) -> np.ndarray:
    """
    将到达时间，数据流向，tcp 或者 udp 数据包装成 hdr 数据，存为 np.ndarray 类型；
    在这里将数据 log 一次。
    Args:
        inter_arrival_time: 数据到达时间
        direction: 数据流向
        tcp: tcp 数据，可能为空但和 udp 必须有一个存在
        udp: udp 数据，可能为空但和 tcp 必须有一个存在

    Returns:
        np.ndarray: 将原始数据载体长度，tcp窗口/udp为0，到达时间，数据流向四个数据装进 numpy 数组
    """
    if tcp is not None:
        hdr = np.array([len(tcp.original), tcp.window, inter_arrival_time, direction]).astype(int)
    elif udp is not None:
        hdr = np.array([len(udp.original), 0, inter_arrival_time, direction]).astype(int)
    else:
        raise ValueError("Either tcp or udp must be specified.")

    # 防止 log(0)
    return np.log(hdr + 10e-4)


class _GladsTask(SessionPreprocessTask):
    """
    GLADS 预处理的实际任务实现。
    它是一个提取 Session 前面部分数据的一种方法。

    在里面保存一个 LRUCache 如果文件太久没使用，将其暂时先保存到文件中（处理结果本身可能就是要保存到文件中，只是暂未处理完成），
    如果需要重新加载一下。

    Attributes:
        N_p (int): 论文参数 n_p, 即保留 HDR 头数据的个数
        N_b (int): 论文参数 n_b, 即保留 PAY 数据最大的长度
        max_pack_len (int): 论文参数, 即单个数据包保存最大的数据载体的长度
        max_seq_len (int): 单个序列最大的长度, N_p * (4 + 4) + N_b, 每个 HDR 头都需要头四个长度, “指示器”四个长度
    """

    def __init__(self, N_p: int = 32, N_b: int = 784, max_pack_len=128, capacity: int = 5000, **kwargs):
        super().__init__(**kwargs)

        self.capacity = capacity

        self.N_p = N_p
        self.N_b = N_b
        self.max_pack_len = max_pack_len
        self.max_seq_len = N_p * (4 + 4) + N_b

        self.cache: OrderedDict[str, _GladsSessionData] = OrderedDict()

        self._logger = get_logger(self.pcap_name)

    def _ignore_packet(self, packet: Packet) -> bool:
        """
        判断给定的包数据是否需要忽略。
        Args:
            packet: 要判断的数据包

        Returns:
            True 如果忽略数据包; 否则 False.
        """
        # 过滤非 TCP、UDP 流量
        if not (packet.haslayer(UDP) or packet.haslayer(TCP)):
            return True
        # 过滤地址 0.0.0.0, 255.255.255.255
        if IP in packet:
            ip: IP = packet[IP]
            if ip.src in ['0.0.0.0', '255.255.255.255'] or ip.dst in ['0.0.0.0', '255.255.255.255']:
                return True
        # 过滤协议层 DNS, DHCP, NTP, SNMP, LLMNR
        layers = [DNS, DHCP, DHCP6, NTP, SNMP, LLMNRQuery, LLMNRResponse]
        for layer in layers:
            if layer in packet:
                return True

        return False

    def get(self, key: str) -> Optional[_GladsSessionData]:
        """
        从缓存中获取数据，如果缓存中没有，尝试从文件中读取。
        Args:
            key: session 键，同时作为数据保存的文件名

        Returns:
            Optional[_GladsSessionData]: 读取到的数据，如果缓存没有并且文件不存在可能为空
        """
        if key in self.cache:
            value = self.cache.pop(key)
            self.cache[key] = value
            return value
        else:
            return self._load_from_file(key)

    def _load_from_file(self, key: str) -> Optional[_GladsSessionData]:
        """
        从文件中加载数据。
        Args:
            key: session 键，作为读取的文件名

        Returns:
            Optional[_GladsSessionData]: 读取到的数据，如果文件不存在可能为空
        """
        file_path = os.path.join(self.output_path, self.relpath, self.pcap_name, key)
        if os.path.exists(file_path):
            with open(file_path, "rb") as f:
                value = pickle.load(f)
                self.cache[key] = value
                if len(self.cache) > self.capacity:
                    self._evict()
                self._logger.debug(f"Loaded {key} from {file_path}")
                return value
        return None

    def _evict(self):
        """
        驱赶 LRU 缓存，将最远未使用的数据存入文件。
        在内存中数据的数量超出了指定的容量的时候调用。
        """
        old_key, old_value = self.cache.popitem(last=False)
        self._save_to_file(old_key, old_value)

    def _save_to_file_by_key(self, key: str) -> None:
        value = self.cache.pop(key)
        self._save_to_file(key, value)

    def _save_to_file(self, key: str, value: _GladsSessionData):
        """
        将数据写入文件。
        Args:
            key: session 键，将作为文件名
            value: 已经统计的数据
        """
        file_path = os.path.join(self.output_path, self.relpath, self.pcap_name, key)
        with open(file_path, "wb") as f:
            pickle.dump(value, f)
            self._logger.debug(f"Saved {key} to {file_path}")

    def pcap_start(self):
        """单个 pcap 文件开始"""
        self.cache = OrderedDict()

    def pcap_completed(self) -> Any:
        while len(self.cache) > 0:
            key, value = self.cache.popitem(last=False)
            self._save_to_file(key, value)
        # TODO 加载数据，处理patch，window等事情
        return []

    def preprocess_session_packet(self, session_key: str, packet: Packet) -> None:
        session_data = self.get(session_key)
        if session_data is None:
            # Session 包第一次到达
            session_data = _GladsSessionData()
            self.cache[session_key] = session_data

        if len(session_data.hdr_list) == self.N_p and session_data.pay_count == self.N_b:
            # 满足数据条件, 保存数据结束
            self.finished_session_keys.append(session_key)
            self._save_to_file_by_key(session_key)
            return

        # 到达时间间隔
        inter_arrival_time = 0 if session_data.last_arrival_time is None else session_data.last_arrival_time
        # 以毫秒计算
        inter_arrival_time *= 1000
        # 保留当前包的到达时间
        session_data.last_arrival_time = packet.time

        # 处理 ip 判断流向
        if not packet.haslayer(IP):
            return
        ip: IP = packet[IP]
        if session_data.server_ip is None:
            # 将第一个包的 dst 当作 server_ip 以判断流向
            # 当然，也可以用 src 地址
            session_data.server_ip = ip.dst
        direction: bool = ip.src == session_data.server_ip

        # 处理 TCP/UDP 的 HDR/载体 数据
        hdr = None
        if packet.haslayer(TCP):
            tcp: TCP = packet[TCP]
            hdr = _extract_hdr(inter_arrival_time, direction, tcp=tcp)
            self._extract_pay(session_data, tcp.payload)

        if packet.haslayer(UDP):
            udp: UDP = packet[UDP]
            hdr = _extract_hdr(inter_arrival_time, direction, udp=udp)
            self._extract_pay(session_data, udp.payload)

        # 保存 hdr
        if hdr is not None and len(session_data.hdr_list) < self.N_p:
            session_data.hdr_list.append(hdr)

    def _extract_pay(self, session_data: _GladsSessionData, payload: Raw) -> None:
        """
        从 packet 包的数据载体中截取部分数据

        截取数据包的长度：
        <载体的长度，需要截取的剩余的长度，最大的截取长度> 三者的最小值。
        即:不能超过载体长度，总长度不能超过 self.N_b, 不能超过最大的截取长度
        Args:
            session_data: session 已经提取的数据
            payload: 数据载体: udp/tcp 的 payload
        """
        pay_len = min(len(payload), self.N_b - session_data.pay_count, self.max_pack_len)
        if pay_len > 0:
            # 截取数据
            pay = np.frombuffer(payload.original[0: pay_len], dtype=np.uint8)
            # 保存截取的数据
            session_data.pay_list.append(pay)
            session_data.pay_count += pay_len


class GladsPreprocessor(PcapPreprocessor):
    """
    实现论文 GLADS 的数据预处理器。

    Attributes:
        N_p (int): 论文参数 n_p, 即保留 HDR 头数据的个数
        N_b (int): 论文参数 n_b, 即保留 PAY 数据最大的长度
        max_pack_len (int): 论文参数, 即单个数据包保存最大的数据载体的长度
    """

    def __init__(self, root_path: str,
                 output_path: str,
                 N_p: int = 32,
                 N_b: int = 784,
                 max_pack_len=128,
                 max_worker=4):
        super(GladsPreprocessor, self).__init__(root_path, output_path, max_workers=max_worker)

        self.N_p = N_p
        self.N_b = N_b
        self.max_pack_len = max_pack_len

    def create_task(self, **kwargs) -> _GladsTask:
        return _GladsTask(capacity=3, **kwargs)
