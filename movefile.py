import csv
import os
import shutil

# 定义源目录和目标目录
source_dir = '/home/shuo/repo/TaintStateMachine/datasets/TN'  # 源目录
target_dir = os.path.join(os.getcwd(), 'dict')  # 当前目录下的dict目录

# 确保目标目录存在
os.makedirs(target_dir, exist_ok=True)

# 读取CSV文件
with open('reference.csv', 'r') as csv_file:
    csv_reader = csv.reader(csv_file)
    
    # 遍历CSV文件的每一行
    for row in csv_reader:
        if row:  # 确保行不为空
            file_name = row[0]  # 获取第一列的文件名
            source_path = os.path.join(source_dir, file_name)
            target_path = os.path.join(target_dir, file_name)
            
            # 检查源文件是否存在
            if os.path.exists(source_path):
                # 复制文件
                shutil.copy2(source_path, target_path)
                print(f"已复制: {file_name}")
            else:
                print(f"文件不存在: {file_name}")

print("复制完成!")