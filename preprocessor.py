import json
import os
import time
from abc import ABC, abstractmethod
from concurrent.futures import ThreadPoolExecutor
from typing import Any

from scapy.packet import Packet
from scapy.utils import PcapReader
from wth.log import get_logger

logger = get_logger("PcapPreprocessor")


class PcapPreprocessTask(ABC):
    """
    pcap 预处理任务, 所有的实现都要实现该抽象类。
    """

    def __init__(self, root_path: str, output_path: str, cur_dir: str, file: str, relpath: str, pcap_name: str):
        """
        构造一个任务预处理任务。
        Args:
            root_path: 数据集所在文件夹
            output_path: 预处理输出文件夹
            cur_dir: 文件所在的文件夹
            file: 文件名, 包含扩展名
            relpath: pcap 文件所在文件夹相对于 root_path 的路径, 为了保持在输出的时候目录结构一致
            pcap_name: pcap 文件名, 不包含扩展名
        """
        self.root_path = root_path
        self.output_path = output_path
        self.cur_dir = cur_dir
        self.file = file
        self.relpath = relpath
        self.pcap_name = pcap_name

    def __call__(self, *args, **kwargs):
        """
        实际的任务处理函数, 线程池最后将调用该方法.
        """
        logger.info(f"文件 {self.relpath}/{self.file} 开始解析...")
        start_time = time.time()
        count = 0
        try:
            # 尝试创建输出文件夹
            self._try_mk_pcap_output_path()

            # 调用回调
            self.pcap_start()
            with PcapReader(f"{self.cur_dir}/{self.file}") as reader:
                for packet in reader:
                    # 处理 packet
                    self.preprocess(packet)
                    count += 1

            # 调用回调
            completed_data = self.pcap_completed()
            # 保存文件处理结果
            self._save_completed_flag(completed_data)
        finally:
            used_time = time.time() - start_time
            logger.info(
                f"文件 {self.relpath}/{self.file} 解析完成! 平均 {count / used_time:.2f} 包/s, "
                f"共{count}包, 用时: {used_time:.3f}s")

    @abstractmethod
    def preprocess(self, packet: Packet):
        """
        对单个包进行数据预处理。
        """
        pass

    def _save_completed_flag(self, completed_data):
        """
        保存文件处理结果.

        将文件处理完成后的回调函数的返回值保存到 completed.json 文件中;
        同时还使用该文件判断文件时候已经解析过了, 如果存在该文件就说明原始 pcap 文件已经处理过了.
        Args:
            completed_data: 单个 pcap 文件处理完成后的回调函数的返回值, 序列化成 json 后保存在 completed.json 文件中。
        """
        if completed_data is None:
            completed_data = []

        output_path = os.path.join(self.output_path, self.relpath, self.pcap_name, "completed.json")
        with open(output_path, "w") as writer:
            json.dump(completed_data, writer)

    def is_preprocessed(self) -> bool:
        """
        判断 pcap 文件是否已经预处理过。
        默认会在路径下生成一个 completed.json 文件，判断该文件是否存在。

        例如:
        处理 /in/A.pcap
        会生成 /out/A/completed.json
        """
        output_path = os.path.join(self.output_path, self.relpath, self.pcap_name, "completed.json")
        return os.path.exists(output_path)

    def pcap_start(self):
        """
        单个 pcap 文件开始处理的回调。
        """
        pass

    def pcap_completed(self) -> Any:
        """
        单个 pcap 文件处理完成的回调。

        Returns:
            单个 pcap 文件处理完成后的回调函数的返回值, 序列化成 json 后保存在 completed.json 文件中。
        """
        pass

    def _try_mk_pcap_output_path(self):
        """
        尝试创建 pcap 解析的输出文件夹。
        """
        output_path = os.path.join(self.output_path, self.relpath, self.pcap_name)
        if not os.path.exists(output_path):
            os.makedirs(output_path)
            logger.debug(f"创建输出文件夹 {output_path}")


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

    def __init__(self, root_path: str, output_path: str, max_workers=19):
        """
        构造函数。
        :param root_path: pcap 所在的文件夹根目录。
        :param output_path: 预处理完成数据保存的根目录。
        """
        self.root_path = root_path
        self.output_path = output_path
        self.max_workers = max_workers
        self.executor = None

    @abstractmethod
    def create_task(self, **kwargs) -> PcapPreprocessTask:
        """
        创建任务, 实际任务需要在 PacaPreprocessTask 中执行.
        PcapPreprocessTask 是个抽象类, 所以还要实现一下 PcapPreprocessTask.
        """

    def start(self):
        # 当前文件夹, _, 当前文件夹下的文件
        self.executor = ThreadPoolExecutor(max_workers=self.max_workers)
        for cur_dir, _, files in os.walk(self.root_path):
            # 当前文件夹相对于 root_path 的路径, 为了保持在输出的时候目录结构一致
            relpath = os.path.relpath(cur_dir, self.root_path)
            for file in files:
                # 忽略文件
                if self.ignore_file(file):
                    continue
                # 不是 pcap 文件
                pcap_name, ext = os.path.splitext(file)
                if not self.is_pcap_file(ext):
                    continue

                # 创建任务
                task = self.create_task(
                    root_path=self.root_path, output_path=self.output_path,
                    cur_dir=cur_dir, file=file, relpath=relpath, pcap_name=pcap_name)

                # 是否已经处理过
                if task.is_preprocessed():
                    # 文件已经处理过
                    logger.warning(f"{pcap_name} 已经处理过, 跳过...")
                    continue

                # 提交任务
                logger.info(f"文件 {relpath}/{file} 解析任务已提交...")
                self.executor.submit(task)

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
