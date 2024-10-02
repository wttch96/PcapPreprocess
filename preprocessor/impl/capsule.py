import os.path

import numpy as np
from PIL import Image
from scapy.packet import Packet

from preprocessor import PcapPreprocessor, PcapPreprocessTask


class _CapsulePreprocessTask(PcapPreprocessTask):

    def __init__(self, M: int, N: int, **kwargs):
        super().__init__(**kwargs)
        self.M = M
        self.N = N

        self.result = []
        self._output_count = 0

    def preprocess(self, packet: Packet):
        """对单个包进行数据预处理。"""
        # 单个包是否需要 pad 到 N
        padding_len = self.N - len(packet.original)
        if padding_len > 0:
            ret = np.frombuffer(packet.original, dtype=np.uint8)
            ret = np.pad(ret, (0, padding_len))
        else:
            ret = np.frombuffer(packet.original[:self.N], dtype=np.uint8)

        self.result.append(ret)
        self._try_save(False)

    def pcap_start(self):
        """
        pcap 文件开始处理。
        """
        self.result = []
        self._output_count = 0

    def pcap_completed(self):
        """
        pcap 文件处理完成。
        """
        self._try_save(True)

    def _try_save(self, completed: bool):
        if not completed and len(self.result) != self.M:
            # 没有处理完成 并且 结果长度不足以保存
            return

        if len(self.result) == 0:
            return

        ret = np.array(self.result)
        if completed and len(ret) != self.M:
            padding_len = 20 - len(ret)
            ret = np.pad(ret, ((0, padding_len), (0, 0)))

        img = Image.fromarray(ret)
        img_path = os.path.join(self.output_path, self.relpath, self.pcap_name,
                                f'{self._output_count}.png')
        img.save(img_path)

        self._output_count += 1
        self.result = []


class CapsulePreprocessor(PcapPreprocessor):
    """
    论文 Capsule Network Assisted IoT Traffic Classification Mechanism for Smart Cities 的数据预处理器实现。

    论文地址: https://ieeexplore.ieee.org/abstract/document/8651277
    """
    result: [np.ndarray]

    def __init__(self, M: int, N: int, root_path: str, output_path: str):
        """
        构造函数。
        :param M: 论文中的参数, 流的个数。
        :param N: 论文中的参数, 每个流保留的前 N 个字节。
        :param root_path: pcap 所在的文件夹根目录。
        :param output_path: 预处理完成数据保存的根目录。
        """
        super(CapsulePreprocessor, self).__init__(root_path, output_path)
        self.M = M
        self.N = N

        self._output_count = 0

    def create_task(self, **kwargs) -> _CapsulePreprocessTask:
        return _CapsulePreprocessTask(self.M, self.N, **kwargs)

    def __repr__(self):
        return (f'Capsule:\n\tM: {self.M}\n\tN: {self.N}\n\t'
                f'root_path: {self.root_path}\n\toutput_path: {self.output_path}')
