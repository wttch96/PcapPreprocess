from abc import ABC, abstractmethod
from collections import OrderedDict

from scapy.packet import Packet

from preprocessor import PcapPreprocessTask

from util.session import session_extractor


class SessionPreprocessTask(PcapPreprocessTask, ABC):
    """
    关于 Session 处理的预处理器。

    一般对于 Session 的处理都是保留前面一部分数据，所以保存一下已经处理完成的 Session key 后面再出现相同的 Session 直接丢弃就可以了。
    Attributes:
        finished_session_keys (list[str]): 已经处理完成的 session key 列表
    """

    def __init__(self, **kwargs):
        super().__init__(**kwargs)

        self.finished_session_keys: list[str] = []

    @abstractmethod
    def preprocess_session_packet(self, session_key: str, packet: Packet) -> None:
        """
        实际的处理的函数，已不再使用 `preprocess`，`preprocess`方法会进行判断，然后交给此函数处理。
        Args:
            session_key: 根据数据包生成的 session 键
            packet: 要处理的数据包
        """
        pass

    def preprocess(self, packet: Packet):
        """
        预处理数据包，对数据包提取 session 键，如果 session 已经处理完成则直接跳过。
        Args:
            packet: 要处理的数据包
        """
        session_key = session_extractor(packet)

        # 如果 Session 已经处理完成
        if session_key in self.finished_session_keys:
            return

        # 未处理完成继续处理
        self.preprocess_session_packet(session_key, packet)
