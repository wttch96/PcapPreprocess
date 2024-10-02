import json
import os
import time
from abc import ABC, abstractmethod
from concurrent.futures import ProcessPoolExecutor
from typing import Any

from scapy.packet import Packet
from scapy.utils import PcapReader
from wth.log import get_logger

logger = get_logger("PcapPreprocessor")


class PcapPreprocessTask(ABC):
    """
    pcap 预处理任务, 所有的实现都要实现该抽象类作为任务分发处理的实际处理模块。
    多文件读取可能存在 IO 瓶颈，故使用多线程来读取 pcap 文件。
    """

    def __init__(self, root_path: str, output_path: str, cur_dir: str, file: str, relpath: str, pcap_name: str):
        """
        构造一个任务预处理任务。 一般这个参数都是由 `PcapPreprocessor#create_task(**kwargs)` 函数生成的, 只需把 `create_task`
        方法的 `kwargs` 作为输入传入该构造函数就可以了。

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

        self.logger = get_logger("PcapPreprocessorTask")

    def __call__(self, *args, **kwargs):
        """
        实际的任务处理函数, 线程池最后将调用该方法.
        """
        logger.info(f"文件 {self.relpath}/{self.file} 开始解析...")
        start_time = time.time()
        count = 0
        ignore_count = 0
        try:
            # 尝试创建输出文件夹
            self._try_mk_pcap_output_path()

            # 调用回调
            self.pcap_start()
            with PcapReader(f"{self.cur_dir}/{self.file}") as reader:
                for packet in reader:
                    # 如果是忽略的数据包
                    if self._ignore_packet(packet):
                        ignore_count += 1
                        continue
                    # 处理 packet
                    self._preprocess_wrapper(packet)
                    count += 1
                    if count % 10000 == 0:
                        used_time = time.time() - start_time
                        logger.info(
                            f"文件 {self.relpath}/{self.file} 已处理{count}包, 忽略{ignore_count}包, 用时: {used_time:.3f}s "
                            f"平均 {count / used_time:.2f} 包/s, ")

            # 调用回调
            completed_data = self.pcap_completed()
            # 保存文件处理结果
            self._save_completed_flag(completed_data)
        except Exception as e:
            logger.exception(e)
        finally:
            used_time = time.time() - start_time
            logger.info(
                f"文件 {self.relpath}/{self.file} 解析完成! 忽略{ignore_count}包, 平均 {count / used_time:.2f} 包/s, "
                f"共{count}包, 用时: {used_time:.3f}s")

    def _preprocess_wrapper(self, packet: Packet) -> None:
        """
        对 preprocess 进行包装, 处理下异常.
        """
        try:
            self.preprocess(packet)
        except Exception as e:
            self.logger.warning(f"预处理包出错 {e.__class__.__name__}: {e}")

    def _ignore_packet(self, packet: Packet) -> bool:
        """
        判断给定的包数据是否需要忽略，默认全部不忽略，如果需要忽略在子类中覆盖此函数即可。
        Args:
            packet: 要判断的数据包

        Returns:
            True 如果忽略数据包; 否则 False.
        """
        return False

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
            return

        output_path = os.path.join(self.output_path, self.relpath, self.pcap_name, "completed.json")
        with open(output_path, "w") as writer:
            json.dump(completed_data, writer)

    @property
    def completed_output_path(self) -> str:
        return os.path.join(self.output_path, self.relpath, self.pcap_name)

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
        Args:
            root_path: pcap 所在的文件夹根目录。
            output_path: 预处理完成数据保存的根目录。
            max_workers: 开启的处理线程数。
        """
        self.root_path = root_path
        self.output_path = output_path
        self.max_workers = max_workers
        self.executor = None

        self._logger = get_logger(self.__class__.__name__)

    @abstractmethod
    def create_task(self, **kwargs) -> PcapPreprocessTask:
        """
        创建任务, 实际任务需要在 PacaPreprocessTask 中执行.
        PcapPreprocessTask 是个抽象类, 所以还要实现一下 PcapPreprocessTask.

        Args:
            kwargs: 处理器框架使用的参数, 直接交给 `PcapPreprocessTask` 的构造函数即可。
        """

    def start(self):
        self._logger.info(f"Start PcapPreprocessor: {self.__class__.__name__}\n"
                          f"\t root_path: {self.root_path}\n"
                          f"\t output_path: {self.output_path}\n"
                          f"\t Max workers: {self.max_workers}")
        # 当前文件夹, _, 当前文件夹下的文件
        self.executor = ProcessPoolExecutor(max_workers=self.max_workers)
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

    # 处理完成的数据
    # def start_process_completed_file(self):
    #     for cur_dir, _, files in os.walk(self.output_path):
    #         for file in files:
    #             file_key = self.completed_file_key(cur_dir, file)
    #
    #             with open(os.path.join(cur_dir, file), 'r') as f:
    #                 content: dict = json.load(f)
    #                 self.process_completed_file(file_key, content)
    #
    # @abstractmethod
    # def process_completed_file(self, file_key: str, content: dict) -> None:
    #     pass
    #
    # @abstractmethod
    # def completed_file_key(self, cur_dir: str, file: str) -> str:
    #     pass

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
