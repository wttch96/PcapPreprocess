from argparse import ArgumentParser

from config import Config

#
# for dataset in Config()['capsule']['datasets']:
#     preprocessor = CapsulePreprocessor(M=dataset['M'], N=dataset['N'], root_path=dataset['root-path'],
#                                        output_path=dataset['output-path'])
#
#     preprocessor.start()


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
        preprocessor = config.preprocessor(args.start)
        preprocessor.start()
