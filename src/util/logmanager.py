import logging


def setuplogger(logname=None):
    if logname is None:
        logname = "globalData"

    # 创建或获取一个日志记录器
    logger = logging.getLogger(logname)

    # 如果记录器已经配置过处理器，则直接返回
    if logger.handlers:
        return logger

    logger.setLevel(logging.DEBUG)  # 设置为DEBUG，捕获所有级别的日志

    # 配置文件处理器，用于写入日志文件
    handler = logging.FileHandler(f"./evaluation/{logname}.log")
    handler.setLevel(logging.INFO)  # 文件处理器也设置为DEBUG

    # 配置日志格式
    formatter = logging.Formatter("%(asctime)s, %(name)s, %(levelname)s, %(message)s")
    handler.setFormatter(formatter)

    # 将处理器添加到日志记录器
    logger.addHandler(handler)

    # 设置为False，避免日志消息传播到更高级别的记录器
    logger.propagate = True

    return logger
