from wth.utils.config import Config as _Config


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
        dataset = self.datasets[dataset_name]
        print(f"    处理方法[{method_name}]")
        print(f"        方法处理类: {1}.{2}")
        print(f"    数据集[{dataset_name}]\n"
              f"        {dataset}")
        print(f"    参数:\n"
              f"        {preprocessor['kwargs']}")
        print(f"    输出路径: {preprocessor['output-path']}")
