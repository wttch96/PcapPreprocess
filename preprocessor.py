import os
import sys
from abc import ABC, abstractmethod

from scapy.packet import Packet
from scapy.utils import PcapReader
from tqdm import tqdm
from wth.utils.progress import bar_format


class PcapPreprocessor(ABC):
    """
    预处理器的基类，相关处理 pcap 文件的基础放在该类中。

    每一个大的 pcap 文件，将被拆分成 1 到 多个 pcap 文件或其他文件。
    按照原 root_path 下的组织结构，将其整理到 output_path 下。

    例如:
    root_path = /I
    output_path = /O
    /I/A/B/C/d.pcap ---> /O/A/B/C/d/*
    将 d.pcap 的 d 作为输出文件夹放入, 上层文件夹结构和输入一致。
    """

    def __init__(self, root_path: str, output_path: str):
        self.root_path = root_path
        self.output_path = output_path

    def start(self):
        # 当前文件夹, _, 当前文件夹下的文件
        for cur_dir, sub_dirs, files in os.walk(self.root_path):
            # 当前文件夹相对于 root_path 的路径, 为了保持在输出的时候目录结构一致
            relpath = os.path.relpath(cur_dir, self.root_path)
            for file in files:
                if self.ignore_file(file):
                    continue

                pcap_name, ext = os.path.splitext(file)
                if not self.is_pcap_file(ext):
                    continue

                if self.is_preprocessed(relpath, pcap_name):
                    continue

                self._try_mk_pcap_output_path(relpath, pcap_name)

                sys.stdout.flush()
                sys.stderr.flush()

                tq = tqdm(unit='Packet', bar_format="已处理:{n_fmt} 速度:{rate_fmt}{postfix} {desc}")
                with PcapReader(f"{cur_dir}/{file}") as reader:
                    for packet in reader:
                        tq.update(1)
                        # 处理 packet
                        output = self.preprocess(packet)
                        # 保存结果
                        self.save_result(output)

    @abstractmethod
    def preprocess(self, packet: Packet):
        pass

    @abstractmethod
    def is_preprocessed(self, relpath: str, pcap_name: str) -> bool:
        pass

    @abstractmethod
    def save_result(self, output):
        pass

    def _try_mk_pcap_output_path(self, relpath: str, pcap_name: str):
        """
        尝试创建 pcap 解析的输出文件夹。
        :param relpath: pcap 文件所在文件夹相对于 root_path 的路径, 为了保持在输出的时候目录结构一致
        :param pcap_name: pcap 的文件名
        """
        output_path = os.path.join(self.output_path, relpath, pcap_name)
        if not os.path.exists(output_path):
            os.makedirs(output_path)
            print(f"创建输出文件夹 {output_path}")

    def ignore_packet(self, p: Packet) -> bool:
        return False

    def ignore_file(self, file: str) -> bool:
        """
        是否是忽略的文件，如果返回 true 将跳过处理。
        只是为了解决 mac 下生成的 .开头的文件
        """
        return file.startswith(".")

    @staticmethod
    def is_pcap_file(ext: str) -> bool:
        """
        判断文件是否为 pcap 文件。使用 splitext 生成的扩展名会有 '.'。
        目前只处理 .pcap 和 .pcapng 格式的文件。

        :param ext: 文件扩展名
        """
        return ext in ['.pcap', '.pcapng']
