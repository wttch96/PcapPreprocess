import os.path
from math import ceil

import numpy as np
from PIL import Image
from scapy.packet import Packet

from preprocessor import PcapPreprocessor


class CapsulePreprocessor(PcapPreprocessor):
    def __init__(self, M: int, N: int, root_path: str, output_path: str):
        super(CapsulePreprocessor, self).__init__(root_path, output_path)
        self.M = M
        self.N = N

        self.result = []

    def preprocess(self, packet: Packet):
        padding_len = self.N - len(packet.original)
        if padding_len > 0:
            ret = np.frombuffer(packet.original, dtype=np.uint8)
            ret = np.pad(ret, (0, padding_len))
        else:
            ret = np.frombuffer(packet.original[:self.N], dtype=np.uint8)

        self.result.append(ret)

    def pcap_start(self):
        self.result = []

    def pcap_completed(self, relpath: str, pcap_name: str):
        ret = np.array(self.result)
        padding_len = ceil(len(ret) / self.M) * self.M - len(ret)
        if padding_len > 0:
            ret = np.pad(ret, ((0, padding_len), (0, 0)))

        ret = ret.reshape((-1, self.M, self.N))

        for i, data in enumerate(ret):
            # 将处理结果保存
            img = Image.fromarray(data)
            img_path = os.path.join(self.output_path, relpath, pcap_name, f'{i}.png')
            img.save(img_path)
