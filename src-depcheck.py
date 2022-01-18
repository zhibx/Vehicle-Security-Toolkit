#!/usr/bin/python3

import argparse
from pathlib import Path
from utils import shell_cmd_ret_code

report_path = Path(__file__).parent.joinpath('data/scan/depcheck')
report_path.mkdir(parents=True, exist_ok=True)


def analysis(src_path: Path):
    print(f'[+] {src_path}')
    report_file = report_path.joinpath(f'{src_path.stem}-depcheck.html')

    scanner = Path(__file__).parent.joinpath('tools/dependency-check/bin/dependency-check.sh')
    cmd = f'{scanner} -s {src_path} -o {report_file}'
    output, ret_code = shell_cmd_ret_code(cmd)

    if not report_file.exists():
        with open(f'{report_file}.error', 'w+') as f:
            f.write(output)

    return ret_code


def argument():
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", help="A config file containing source code paths to run analysis", type=str, required=True)
    return parser.parse_args()


if __name__ == '__main__':
    print('****************** src-depcheck.py *******************')

    failed = []
    success_num = 0
    config_file = argument().config
    if config_file:
        src_dirs = open(config_file, 'r').read().splitlines()

        for src in src_dirs:
            ret = analysis(Path(src))
            if ret == 0:
                success_num += 1
            else:
                failed.append(src)
    else:
        print('[!] 参数错误: python3 src-depcheck.py --help')

    print(f'扫描完成: {success_num}, 扫描失败: {len(failed)}')
    print('\n'.join(failed))
