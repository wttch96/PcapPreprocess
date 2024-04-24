from typing import Any

from scapy.packet import Packet

from preprocessor import PcapPreprocessor, PcapPreprocessTask


class _UstcStatisticsTask(PcapPreprocessTask):

    def preprocess(self, packet: Packet):
        pass

    def pcap_completed(self) -> Any:
        pass


class UstcStatistics(PcapPreprocessor):
    def create_task(self, **kwargs) -> _UstcStatisticsTask:
        pass
