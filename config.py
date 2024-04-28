import importlib

from wth.utils.config import Config as _Config
from wth.utils.reflect import ReflectUtil

from preprocessor import PcapPreprocessor


class Config(_Config):

    def __init__(self):
        super().__init__()
        self.datasets = self.configs.get('datasets', {})
        self.methods = self.configs.get('methods', {})
        self.preprocessors = self.configs.get('preprocessors', {})

    def display_detail(self, name: str) -> None:
        print(f"预处理器[{name}]")
        preprocessor = self.preprocessors[name]
        dataset_name = preprocessor['dataset']
        method_name = preprocessor['method']

        if 'kwargs' in preprocessor:
            print(f"    参数:\n"
                  f"        {preprocessor['kwargs']}")
        print(f"    输出路径: {preprocessor['output-path']}")

        if dataset_name not in self.datasets:
            print(f"    ⚠️数据集{dataset_name}未定义.")
            return
        dataset = self.datasets[dataset_name]
        print(f"    数据集[{dataset_name}]\n"
              f"        {dataset}")

        if method_name not in self.methods:
            print(f"    ⚠️预处理方法{method_name} 未定义.")
            return

        method_params = self.methods[method_name]

        module_name = method_params['module']
        class_name = method_params['class']
        init_args = method_params['init-kwargs'] if 'init-kwargs' in method_params else {}
        method_module = importlib.import_module(module_name)
        method_class = getattr(method_module, class_name)
        method = method_class(
            root_path=dataset['root-path'],
            output_path=preprocessor['output-path']
        )
        print(f"    处理方法[{method_name}]")
        print(f"        方法处理类: {type(method)}")

    def preprocessor(self, name: str) -> PcapPreprocessor:
        preprocessor = self.preprocessors[name]
        dataset_name = preprocessor['dataset']
        method_name = preprocessor['method']
        dataset = self.datasets[dataset_name]
        method_params = self.methods[method_name]

        module_name = method_params['module']
        class_name = method_params['class']
        method_module = importlib.import_module(module_name)
        method_class = getattr(method_module, class_name)
        method = method_class(
            root_path=dataset['root-path'],
            output_path=preprocessor['output-path']
        )
        return method
