import os
import subprocess
from multiprocessing import Pool
import psutil
import csv
import time
import json


def append_to_csv(contract, duration, vul=""):
    filename = f"{vul}_duration.csv"
    file_exists = os.path.isfile(filename)

    with open(filename, "a", newline="") as csvfile:
        fieldnames = ["contract", "duration"]
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)

        if not file_exists:
            writer.writeheader()

        writer.writerow(
            {
                "contract": contract,
                "duration": duration,
            }
        )


def run_process(args):
    file, timeoutsize, vul = args
    starttime = time.time()
    name = file.rsplit("/", 1)[-1]
    cmd = ["python3", "bin/test.py", "-f", file, "-b", "-v", vul, "-t", "early"]
    try:
        subprocess.run(cmd, timeout=timeoutsize)
    except subprocess.TimeoutExpired:
        pass
    finally:
        endtime = time.time()
        duration = endtime - starttime
        append_to_csv(name, duration, vul)


def get_file_list(directory_path):
    filelist = []
    for filename in os.listdir(directory_path):
        if filename.endswith(".hex") or filename.endswith(".code"):
            full_path = os.path.join(directory_path, filename)
            filelist.append(full_path)
    return filelist


def calculate_pool_size():
    mem = psutil.virtual_memory()
    available_memory_gb = mem.available / (1024**3)
    cpu_count = psutil.cpu_count(logical=False)

    memory_per_process_gb = 8
    max_processes_by_memory = int(available_memory_gb / memory_per_process_gb)
    max_processes_by_cpu = cpu_count

    return min(max_processes_by_memory, max_processes_by_cpu)


def main():
    with open("config.json", "r") as file:
        configs = json.load(file)

    num_processes = calculate_pool_size()
    print(f"Starting {num_processes} processes...")

    # Create a single pool for all configurations
    with Pool(num_processes) as pool:
        all_tasks = []

        # Prepare all tasks from all configurations
        for config in configs:
            timeout = config["timeout"]
            from_dir = config["from"]
            vul = config["vul"]

            directory_path = os.path.expanduser(from_dir)
            filelist = get_file_list(directory_path)

            # Create tasks for this configuration
            config_tasks = [(file, timeout, vul) for file in filelist]
            all_tasks.extend(config_tasks)

        # Execute all tasks concurrently
        pool.map(run_process, all_tasks)


if __name__ == "__main__":
    main()
