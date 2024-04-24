from argparse import ArgumentParser

from config import Config
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
    config = Config()
    arg = ArgumentParser("Pcap 预处理器", add_help=True)
    arg.add_argument('--detail', choices=config.preprocessors.keys(), help="显示预处理执行器的详细信息")
    arg.add_argument('--start', choices=config.preprocessors.keys(), help="开始执行数据预处理器")

    args = arg.parse_args()

    if args.detail is not None:
        # 显示预处理器详细信息
        config.display_detail(args.detail)

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
