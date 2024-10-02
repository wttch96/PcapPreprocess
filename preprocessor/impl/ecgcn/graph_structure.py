import os
import pickle
import networkx as nx
from typing import Any

import numpy
from matplotlib import pyplot as plt
from scapy.packet import Packet

from ... import PcapPreprocessor, PcapPreprocessTask


class _ECGENGraphStructureTask(PcapPreprocessTask):

    def __init__(self, root_path: str, output_path: str, cur_dir: str, file: str, relpath: str, pcap_name: str):
        super().__init__(root_path, output_path, cur_dir, file, relpath, pcap_name)
        self.data_len_counter = None
        self.data = None
        self.last_packet_length = None

    def pcap_start(self):
        self.data = numpy.zeros((1600, 1600), dtype=numpy.int32)
        self.data_len_counter = numpy.zeros(1600, dtype=numpy.uint32)
        self.last_packet_length = 0

    def is_preprocessed(self) -> bool:
        return (os.path.exists(os.path.join(self.completed_output_path, "graph.pkl"))
                and os.path.exists(os.path.join(self.completed_output_path, "counter.pkl")))

    def preprocess(self, packet: Packet):
        cur_length = len(packet.original)
        if self.last_packet_length != cur_length:
            self.data[self.last_packet_length][cur_length] += 1
            self.data_len_counter[cur_length] += 1
            self.last_packet_length = cur_length

    def pcap_completed(self) -> Any:
        # 保留大于0的值
        self.data[self.data < 100] = 0
        # 示例邻接矩阵 (numpy 数组)
        adj_matrix = self.data

        # 创建有向图
        G = nx.from_numpy_array(adj_matrix, create_using=nx.DiGraph)

        # 找出所有孤立节点（度为0的节点）
        isolated_nodes = [node for node, degree in dict(G.degree()).items() if degree == 0]
        # 删除孤立节点
        G.remove_nodes_from(isolated_nodes)

        # 绘制图形
        pos = nx.spring_layout(G)  # 使用 spring 布局

        min_count = numpy.min(self.data_len_counter)
        max_count = numpy.max(self.data_len_counter)
        # 根据权重设置节点大小（如通过权重放大10倍来显示差异）
        node_sizes = [10 + 1000 * (self.data_len_counter[node] - min_count) / (max_count - min_count) for node in G.nodes]

        nx.draw(G, pos, with_labels=True, node_size=node_sizes, node_color='lightblue', font_size=6,
                font_weight='bold')

        plt.savefig(os.path.join(self.completed_output_path, "graph.png"), dpi=300)


class ECGENGraphStructurePreprocessor(PcapPreprocessor):

    def __init__(self, root_path: str, output_path: str, max_workers: int):
        super(ECGENGraphStructurePreprocessor, self).__init__(root_path, output_path, max_workers)

    def create_task(self, **kwargs) -> PcapPreprocessTask:
        return _ECGENGraphStructureTask(**kwargs)
