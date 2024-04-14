import time

from scapy.packet import Packet
from wth.utils.config import Config

from preprocessor import PcapPreprocessor


class GLADSPreprocessor(PcapPreprocessor):

    def __init__(self, config: Config):
        glads_config = config['glads']
        datasets = glads_config['datasets'][0]
        super(GLADSPreprocessor, self).__init__(
            root_path=datasets['root-path'],
            output_path=datasets['output-path']
        )

    def preprocess(self, packet: Packet):
        time.sleep(0.1)
        return packet

    def save_result(self, output):
        pass

    def is_preprocessed(self, relpath: str, pcap_name: str) -> bool:
        return False
