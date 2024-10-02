import importlib
import os
from dataclasses import dataclass
from typing import Optional

from wth.log import get_logger
from wth.utils.config import Config as _Config
from wth.utils.dataclass import deserialize
from preprocessor import PcapPreprocessor


@dataclass
class PreprocessorDatasetDeclaration:
    name: str
    description: Optional[str] = None
    url: Optional[str] = None
    root_path: Optional[str] = None


@dataclass
class PreprocessorDatasetConfigDeclaration:
    name: str
    root_path: Optional[str] = None


@dataclass
class PreprocessorMethodDeclaration:
    name: str
    module: str
    clazz: str

    @property
    def class_type(self):
        method_module = importlib.import_module(self.module)
        method_class = getattr(method_module, self.clazz)
        return method_class


@dataclass
class PreprocessorDeclaration:
    name: str
    method: str
    dataset: str
    kwargs: dict[str, str] = None


class Config(_Config):

    def __init__(self):
        super().__init__("pcap-preprocess")
        self._logger = get_logger("Config")
        self.datasets = self._datasets()
        self.methods = self._methods()
        self.preprocessors = self._preprocessors()
        self.output_path = self['output-path']

    def _datasets(self) -> dict[str, PreprocessorDatasetDeclaration]:
        """ 获取 name 到 数据集定义 的映射"""
        datasets: list[PreprocessorDatasetDeclaration] = deserialize(
            self['datasets'],
            list[PreprocessorDatasetDeclaration])
        datasets_config: dict[str: PreprocessorDatasetConfigDeclaration] = {
            config.name: config
            for config in deserialize(
                self['datasets-config'],
                list[PreprocessorDatasetConfigDeclaration]
            )
        }
        # 装配数据集路径
        for dataset in datasets:
            if dataset.name in datasets_config:
                config = datasets_config[dataset.name]
                if config.root_path is not None and config.root_path != '':
                    dataset.root_path = config.root_path
                    continue
            self._logger.error(f"Dataset '{dataset.name}' is not config root path or root path is empty!")

        return {dataset.name: dataset for dataset in datasets}

    def _methods(self) -> dict[str, PreprocessorMethodDeclaration]:
        """获取 name 到 处理器方法 的映射"""
        methods = deserialize(self['methods'], list[PreprocessorMethodDeclaration])
        return {method.name: method for method in methods}

    def _preprocessors(self) -> dict[str, PreprocessorDeclaration]:
        """ 获取 name 到 预处理器实例 的映射 """
        preprocessors: list[PreprocessorDeclaration] = deserialize(self['preprocessors'], list[PreprocessorDeclaration])

        for preprocessor in preprocessors:
            if preprocessor.method not in self.methods:
                self._logger.error(
                    f"Preprocessor '{preprocessor.name}' method '{preprocessor.method}' is not defined!")
            if preprocessor.dataset not in self.datasets:
                self._logger.error(
                    f"Preprocessor '{preprocessor.name}' dataset '{preprocessor.dataset}' is not defined!")

        return {preprocessor.name: preprocessor for preprocessor in preprocessors}

    def preprocessor(self, name: str) -> PcapPreprocessor:
        preprocessor = self.preprocessors[name]
        kwargs = preprocessor.kwargs if preprocessor.kwargs is not None else {}
        dataset = self.datasets[preprocessor.dataset]
        method_type = self.methods[preprocessor.method].class_type

        method = method_type(
            root_path=dataset.root_path,
            output_path=os.path.join(self.output_path, name),
            **kwargs
        )
        return method
