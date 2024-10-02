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
    arg.add_argument("--show-methods", action="store_true", help="Show methods")
    arg.add_argument('--start', choices=config.preprocessors.keys(), help="开始执行数据预处理器")

    args = arg.parse_args()

    if args.show_methods:
        for method in config.methods.values():
            print(method.name)
    else:
        preprocessor = config.preprocessor(args.start)
        preprocessor.start()
