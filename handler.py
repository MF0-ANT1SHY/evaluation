import os
import subprocess
from multiprocessing import Pool
import psutil
from src.util.logmanager import setuplogger
import csv
import time


def append_to_csv(contract, duration):
    filename = "timeout_cases.csv"
    file_exists = os.path.isfile(filename)

    with open(filename, "a", newline="") as csvfile:
        fieldnames = ["contract", "duration"]
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)

        if not file_exists:
            writer.writeheader()  # 如果文件不存在，写入标题行

        writer.writerow(
            {
                "contract": contract,
                "duration": duration,
            }
        )

def run_process(file, timeoutsize=5 * 60):
    logger = setuplogger()
    name = file.rsplit("/", 1)[-1]
    """运行单个处理进程"""
    cmd = ["python3", "bin/analyzer.py", "-f", file, "-b"]
    start_time = time.time()
    try:
        subprocess.run(cmd, timeout=timeoutsize)
    except subprocess.TimeoutExpired:
        duration = timeoutsize
        print(f"timeout")
        print(f"append to {name} and {duration} ")
        append_to_csv(name, duration)
        logger.info(
            f"{name},{None},{True},{None},{None},{None},{None},{None},{None},{timeoutsize},{None},{None}"
        )


def main():
    # 获取系统的内存和CPU信息
    mem = psutil.virtual_memory()
    available_memory_gb = mem.available / (1024**3)  # 可用内存转换为GB
    cpu_count = psutil.cpu_count(logical=False)  # 获取物理核心数

    # 假设每个进程需要6GB内存
    memory_per_process_gb = 6
    max_processes_by_memory = int(available_memory_gb / memory_per_process_gb)
    max_processes_by_cpu = cpu_count

    # 取内存和CPU允许的最小值作为并发进程数
    num_processes = min(max_processes_by_memory, max_processes_by_cpu)

    print(f"Starting {num_processes} processes...")

    directories = [
        #os.path.expanduser("./datasets/popular_contracts/bytecode"),
        os.path.expanduser("./datasets/annotated/bytecode"),
    ]

    archivefile = "archivelist.csv"

    timeoutlimit = 30*60

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
