import os
import subprocess
from multiprocessing import Pool
import psutil
from src.util.logmanager import setuplogger
import csv


def run_process(file, timeoutsize=2 * 60):
    print(f"analyzing {file}...")
    logger = setuplogger()
    name = file.rsplit("/", 1)[-1]
    """运行单个处理进程"""
    cmd = ["python3", "bin/analyzer.py", "-f", file, "-b"]
    try:
        subprocess.run(cmd, timeout=timeoutsize)
    except subprocess.TimeoutExpired:
        logger.info(
            f"{name},{None},{True},{None},{None},{None},{None},{None},{None},{timeoutsize},{None},{None}"
        )


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

    directories = [
        os.path.expanduser("/home/shuo/repo/TaintStateMachine/datasets/TN"),
        #os.path.expanduser("/home/shuo/repo/evaluation"),
    #    /home/shuo/repo/evaluation
    ]

    archivefile = "archivelist.csv"

    timeoutlimit = 60*30

    analyzed_filenames = set()
    with open(archivefile, newline="") as csvfile:
        reader = csv.reader(csvfile)
        for row in reader:
            if len(row) > 3:  # 确保行有足够的列
                analyzed_filenames.add(row[4].strip())

    pool = Pool(num_processes)
    print(pool._cache)
    print(f"{len(analyzed_filenames)} files have been analyzed before.")

    filelist = []

    # 遍历目录中的文件
    for directory_path in directories:
        for filename in os.listdir(directory_path):
            if filename.endswith(".code"):
                # 检查文件是否已经被分析过
                if filename in analyzed_filenames:
                    continue  # 已分析过的文件跳过不处理
                full_path = os.path.join(directory_path, filename)
                filelist.append(full_path)

    for path in filelist:
        pool.apply_async(
            run_process,
            (
                path,
                timeoutlimit,
            ),
        )
    pool.close()
    pool.join()


if __name__ == "__main__":
    main()
