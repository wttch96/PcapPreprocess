from argparse import ArgumentParser

from wth.utils.config import Config

from impl.capsule import CapsulePreprocessor
from preprocessor import PcapPreprocessor

#
# for dataset in Config()['capsule']['datasets']:
#     preprocessor = CapsulePreprocessor(M=dataset['M'], N=dataset['N'], root_path=dataset['root-path'],
#                                        output_path=dataset['output-path'])
#
#     preprocessor.start()

METHOD = {
    'capsule': lambda x: CapsulePreprocessor(x['M'], x['N'], x['root-path'], x['output-path'])
}

if __name__ == '__main__':
    arg = ArgumentParser("Pcap 预处理器", add_help=True)
    arg.add_argument('--show-methods', action='store_true', help="显示所有可以预处理的数据集和配置的数据集")
    arg.add_argument('--method', type=str, help="要处理的数据集方法, 需要已经配置在 config.yml")
    arg.add_argument('--dataset', type=str, help="要处理的数据集名称, 需要已经配置在 config.yml")

    args = arg.parse_args()

    config = Config()

    if args.show_methods:
        for k, v in config.configs.items():
            print(f"{k}:")
            for dataset in v['datasets']:
                print(f"\t{dataset['name']}")
    else:
        method = args.method
        dataset = args.dataset

        if method in config.configs:
            datasets = {k['name']: k for k in config.configs[method]['datasets']}
            if dataset in datasets:
                method_config = datasets[dataset]
                processor = METHOD[method](method_config)  # type: PcapPreprocessor
                print(processor)
                processor.start()
            else:
                print(f"未知的数据集: {dataset} 期望:{','.join(datasets.keys())}")
        else:
            print(f"未知的数据集处理方法:{method} 期望:{','.join(config.configs.keys())}")
