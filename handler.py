import os
import glob
import subprocess
from multiprocessing import Pool
import psutil
import time


def run_process(file):
    """运行单个处理进程"""
    cmd = f"python bin/analyzer.py -f {file} -b "
    subprocess.run(cmd, shell=True)


def main():
    # 获取系统的内存和CPU信息
    mem = psutil.virtual_memory()
    available_memory_gb = mem.available / (1024**3)  # 可用内存转换为GB
    cpu_count = psutil.cpu_count(logical=False)  # 获取物理核心数

    # 假设每个进程需要8GB内存
    memory_per_process_gb = 8
    max_processes_by_memory = int(available_memory_gb / memory_per_process_gb)
    max_processes_by_cpu = cpu_count

    # 取内存和CPU允许的最小值作为并发进程数
    num_processes = min(max_processes_by_memory, max_processes_by_cpu)

    print(f"Starting {num_processes} processes...")
    time.sleep(5)

    directories = [
        os.path.expanduser("datasets/Ethereum/bytecode"),
    ]

    pool = Pool(num_processes)
    print(pool._cache)

    filelist = []

    for directory_path in directories:
        for filename in os.listdir(directory_path):
            if filename.endswith(".code"):
                full_path = os.path.join(directory_path, filename)
                filelist.append(full_path)

    for path in filelist:
        pool.apply_async(run_process, (path,))
    pool.close()
    pool.join()


if __name__ == "__main__":
    main()
