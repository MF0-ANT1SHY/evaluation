#!/usr/bin/env python3
import json
import logging
import resource
import psutil
import signal
import sys
import argparse
import multiprocessing
from multiprocessing import Pool
import subprocess
import os
import gc
import shlex
import re
import time
from src.project import Project
from src.cfg import opcodes
from src.slicing import interesting_slices, slice_to_program
from src.explorer.forward import ForwardExplorer
import src.cfg.rattle as rattle
from collections import defaultdict
from src.flow.analysis_results import TainitAnalysisBugDetails
import src.flow.code_info as cinfo
import src.flow.analysis_results as analysis_results
from src.util.logmanager import setuplogger

timeout_seconds = 5 * 60  # 超时时间


class TimeoutException(Exception):
    pass


def handle_timeout(signum, frame):
    raise TimeoutException("Execution timed out")


# logging.basicConfig(level=logging.INFO)

logging.basicConfig(level=logging.INFO)


def hex_encode(d):
    return {k: v.hex() if isinstance(v, bytes) else v for k, v in d.items()}


def extract_bin_str(s):
    """
    Extracts binary representation of smart contract from solc output.
    """
    # binary_regex = r"\r?\n======= (.*?) =======\r?\nBinary of the runtime part: \r?\n(.*?)\r?\n"
    binary_regex = (
        r"\r?\n======= (.*?) =======\r?\nBinary of the runtime part:\r?\n(.*?)\r?\n"
    )

    contracts = re.findall(re.compile(binary_regex), s.decode("utf-8"))
    contracts = [contract for contract in contracts if contract[1]]

    if not contracts:
        logging.critical("Solidity compilation failed")
        print("======= error =======")
        print("Solidity compilation failed")
        print("Check the used solc compiler version")
        exit()
    return contracts


def link_libraries(filename, libs):
    """
    Compiles contract in filename and links libs by calling solc --link. Returns binary representation of linked contract.
    """
    option = ""
    for idx, lib in enumerate(libs):
        lib_address = "0x" + hex(idx + 1)[2:].zfill(40)
        option += " --libraries %s:%s" % (lib, lib_address)
    FNULL = open(os.devnull, "w")
    cmd = "solc --bin-runtime %s" % filename
    p1 = subprocess.Popen(shlex.split(cmd), stdout=subprocess.PIPE, stderr=FNULL)
    cmd = "solc --link%s" % option
    p2 = subprocess.Popen(
        shlex.split(cmd), stdin=p1.stdout, stdout=subprocess.PIPE, stderr=FNULL
    )
    p1.stdout.close()
    out = p2.communicate()[0]
    return extract_bin_str(out)


def get_evm(contract):
    cmd = "solc --bin-runtime %s" % contract
    FNULL = open(os.devnull, "w")
    solc_p = subprocess.Popen(shlex.split(cmd), stdout=subprocess.PIPE, stderr=FNULL)
    out = solc_p.communicate()[0]
    return extract_bin_str(out)


def analysis(
    p,
    initial_storage=dict(),
    initial_balance=None,
    max_calls=3,
    controlled_addrs=set(),
    flags=None,
):
    user_alerts = {
        "Unbounded-Loop": "Unbounded loop condition",
        "DoS-With-Failed-Call": "DoS-With-Failed-Call",
    }
    flags = flags or set(opcodes.CRITICAL)
    tainting_type = "storage"
    ##convert_to_ssa
    sys.setrecursionlimit(10000)
    ssa = rattle.Recover(
        bytes.hex(p.code).encode(), edges=p.cfg.edges(), split_functions=False
    )

    projectinstance = p
    ULisworth = True
    DFisworth = True
    process = psutil.Process(os.getpid())
    peak_memory_use = 0
    unbounded_count = 0
    unbounded_restr_count = 0
    loop_calls_count = 0
    griefing_count = 0
    harcoded_count = 0
    asserts_count = 0
    temp_slots_count = 0
    slot_live_access_count = 0

    for defect_type in list(["Unbounded-Loop", "DoS-With-Failed-Call"]):
        print("Checking contract for \033[4m{0}\033[0m ".format(defect_type))
        print("------------------\n")
        ins = []
        taintedBy = []

        if defect_type == "Unbounded-Loop":
            loops = p.cfg.find_loops()
            for loop, heads in loops.items():
                for h in set(heads[1:]):
                    ins.append(p.cfg._bb_at[h].ins[-1])
                restricted = True

        elif defect_type == "DoS-With-Failed-Call":
            loops = p.cfg.find_loops(with_calls=True)
            for loop, heads in loops.items():
                for h in set(heads):
                    ins.append(h)
            restricted = True
        else:
            ins = []
        if not ins:
            # isworth = False
            if defect_type == "Unbounded-Loop":
                ULisworth = False
            elif defect_type == "DoS-With-Failed-Call":
                DFisworth = False
            continue
        vulnerable_loops = []
        loops_with_calls = []
        analysis_results.analyzed_sinks()
        ins_types = (
            set(s.name for s in ins) & frozenset(["JUMPI", "LT", "GT", "ISZERO"])
            if defect_type in set(["Unbounded-Loop"])
            else set(s.name for s in ins)
        )
        for ins_type in ins_types:
            if defect_type in (["DoS-With-Failed-Call"]):
                args = [1]
            else:
                args = opcodes.CRITICAL_ARGS[ins_type]
            sub_ins = set([s for s in ins if s.name == ins_type])
            if defect_type in (["DoS-With-Failed-Call"]):
                sinks = {s.addr: [1] for s in sub_ins}
            else:
                sinks = {s.addr: opcodes.CRITICAL_ARGS[ins_type] for s in sub_ins}

            if taintedBy == []:
                taintedBy = opcodes.potentially_user_controlled
            for i, i_path, i_r in p.extract_paths(
                ssa,
                sub_ins,
                sinks,
                taintedBy,
                defect_type=defect_type,
                args=args,
                restricted=restricted,
                memory_info=None,
            ):
                logging.debug("%s: %s", ins_type, i)
                logging.debug("Path: %s", "->".join("%x" % p for p in i_path))
                if i_r._tainted:
                    logging.debug("Path: %s", "->".join("%x" % p for p in i_path))
                    sload_slots = [
                        v
                        for i in i_r.sources
                        for k, v in i.items()
                        if k.startswith("SLOAD")
                    ]
                    sload_sha3_bases = {
                        i: i_r.sload_sha3_bases[i]
                        for i in i_r.sload_sha3_bases
                        if i in sload_slots
                    }
                    callvalue_source = [
                        k
                        for i in i_r.sources
                        for k, v in i.items()
                        if k.startswith("CALLVALUE")
                    ]
                    if len(sload_slots) == 0:
                        if defect_type in (["Unbounded-Loop"]) and (
                            tainting_type != "storage" or len(callvalue_source) != 0
                        ):
                            vulnerable_loops.append(
                                {
                                    "block": i_path[-2],
                                    "function": cinfo.get_function_sig(p, i_path),
                                    "ins": i,
                                    "loop_restricted": cinfo.function_restricted_caller(
                                        p, i_path
                                    ),
                                    "increased_in": None,
                                    "increase_restricted": None,
                                }
                            )
                            analysis_results.checked_sinks.append(i)
                        elif defect_type in (["DoS-With-Failed-Call"]) and (
                            tainting_type != "storage" or len(callvalue_source) != 0
                        ):
                            loops_with_calls.append(
                                {
                                    "block": i_path[-2],
                                    "function": cinfo.get_function_sig(p, i_path),
                                    "ins": i,
                                    "loop_restricted": cinfo.function_restricted_caller(
                                        p, i_path
                                    ),
                                    "increased_in": None,
                                    "increase_restricted": None,
                                }
                            )
                            analysis_results.checked_sinks.append(i)
                        elif defect_type in (["Gas-Griefing"]):
                            griefing_count += 1
                        elif defect_type in (["Hardcoded-Gas"]):
                            harcoded_count += 1
                        if defect_type not in (
                            ["Unbounded-Loop", "DoS-With-Failed-Call"]
                        ):
                            print(
                                "{0} at statment {1} in function: {2}".format(
                                    user_alerts[i_r.defect_type],
                                    i,
                                    cinfo.get_function_sig(p, i_path),
                                )
                            )
                            print("------------------\n")
                    elif (
                        defect_type in (["Gas-Griefing"])
                        and len(
                            [
                                v
                                for i in i_r.sources
                                for k, v in i.items()
                                if not k.startswith("SLOAD")
                            ]
                        )
                        != 0
                    ):
                        griefing_count += 1
                        print(
                            "{0} at statment {1} in function: {2}".format(
                                user_alerts[i_r.defect_type],
                                i,
                                cinfo.get_function_sig(p, i_path),
                            )
                        )
                        print("------------------\n")
                    else:
                        sstores = p.cfg.filter_ins("SSTORE", reachable=True)
                        sstore_sinks = {s.addr: [1] for s in sstores}
                        sstore_taintedBy = opcodes.potentially_direct_user_controlled
                        for s, s_path, s_r in p.extract_paths(
                            ssa,
                            sstores,
                            sstore_sinks,
                            sstore_taintedBy,
                            defect_type="Storage-Tainting",
                            args=[1],
                            storage_slots=sload_slots,
                            storage_sha3_bases=sload_sha3_bases,
                            restricted=True,
                        ):
                            logging.debug("%s: %s", "SSTORE", s)
                            logging.debug(
                                "Path: %s", "->".join("%x" % p for p in s_path)
                            )
                            if s_r._tainted:
                                analysis_results.checked_sinks.append(i)
                                logging.debug(
                                    "Path: %s", "->".join("%x" % p for p in s_path)
                                )
                                if defect_type in (["Unbounded-Loop"]):
                                    vulnerable_loops.append(
                                        {
                                            "block": i_path[-2],
                                            "function": cinfo.get_function_sig(
                                                p, i_path
                                            ),
                                            "ins": i,
                                            "loop_restricted": cinfo.function_restricted_caller(
                                                p, i_path
                                            ),
                                            "increased_in": cinfo.get_function_sig(
                                                p, s_path
                                            ),
                                            "increase_restricted": cinfo.function_restricted_caller(
                                                p, s_path
                                            ),
                                        }
                                    )
                                elif defect_type in (["DoS-With-Failed-Call"]):
                                    loops_with_calls.append(
                                        {
                                            "block": i_path[-2],
                                            "function": cinfo.get_function_sig(
                                                p, i_path
                                            ),
                                            "ins": i,
                                            "loop_restricted": cinfo.function_restricted_caller(
                                                p, i_path
                                            ),
                                            "increased_in": cinfo.get_function_sig(
                                                p, s_path
                                            ),
                                            "increase_restricted": cinfo.function_restricted_caller(
                                                p, s_path
                                            ),
                                        }
                                    )
                                elif defect_type in (["Gas-Griefing"]):
                                    griefing_count += 1
                                elif defect_type in (["Hardcoded-Gas"]):
                                    harcoded_count += 1
                                if defect_type not in (
                                    ["Unbounded-Loop", "DoS-With-Failed-Call"]
                                ):
                                    print(
                                        "{0} at statment {1} in function: {2}".format(
                                            user_alerts[i_r.defect_type],
                                            i,
                                            cinfo.get_function_sig(p, i_path),
                                        )
                                    )
                                    print("------------------\n")
                                break
        if defect_type in (["Unbounded-Loop"]):
            for l, hd in loops.items():
                r = 0
                v_ins = [b for b in vulnerable_loops if b["block"] in set(hd[1:])]
                no_storage_tnt = [
                    b
                    for b in vulnerable_loops
                    if b["block"] in set(hd[1:]) and b["increased_in"] is None
                ]
                if len(v_ins) != 0:
                    if hd[0] < 3 and len(no_storage_tnt) != 0:
                        continue
                    print(
                        "{0} in function: {1}".format(
                            user_alerts[i_r.defect_type], v_ins[0]["function"]
                        )
                    )
                    for v in v_ins:
                        if v["increased_in"] is not None:
                            if v["increase_restricted"]:
                                r += 1
                                print(
                                    "Following loop bound is tainted in function {0} (restricted calls)".format(
                                        v["increased_in"]
                                    )
                                )
                            else:
                                print(
                                    "Following loop bound is tainted in function {0}".format(
                                        v["increased_in"]
                                    )
                                )
                        print(v["ins"])
                    print("\n")
                    if r == 0:
                        unbounded_count += 1
                    else:
                        unbounded_restr_count += 1
        if defect_type in (["DoS-With-Failed-Call"]):
            for l, hd in loops.items():
                r1 = 0
                v_ins = [b for b in loops_with_calls if b["block"] in set([l])]
                if len(v_ins) != 0:
                    loop_calls_count += 1
                    print(
                        "{0} in function: {1}".format(
                            user_alerts[i_r.defect_type], v_ins[0]["function"]
                        )
                    )
                    for v in v_ins:
                        if v["increased_in"] is not None:
                            print(
                                "Following call target is tainted in function {0}".format(
                                    v["increased_in"]
                                )
                            )
                        print(v["ins"])
                    print("\n")
    current_memory = process.memory_info().rss / (1024 * 1024)
    if current_memory > peak_memory_use:
        peak_memory_use = current_memory
    return (
        TainitAnalysisBugDetails(
            unbounded_count,
            unbounded_restr_count,
            loop_calls_count,
            griefing_count,
            harcoded_count,
            asserts_count,
            slot_live_access_count,
            temp_slots_count,
        ),
        peak_memory_use,
        projectinstance.cfg.jumpcount,
        ULisworth,
        DFisworth,
    )


def parse_arguments():
    parser = argparse.ArgumentParser()
    grp = parser.add_mutually_exclusive_group(required=True)
    grp.add_argument(
        "-f",
        "--file",
        type=str,
        help="Code source file. Solidity by default. Use -b to process evm instead. Use stdin to read from stdin.",
    )
    parser.add_argument(
        "-b",
        "--bytecode",
        action="store_true",
        help="read bytecode in source instead of solidity file.",
    )
    parser.add_argument("-m", "--memory", help="Max memory limit")
    parser.add_argument("--initial_storage_file", help="initial storage file")
    parser.add_argument("-sf", "--savefile")
    parser.add_argument(
        "-tt",
        "--tainting-type",
        choices=["all", "storage"],
        help="tainting type could be 'all' or 'storage'",
    )
    return parser.parse_args()


def configure_memory_limits(memory_arg):
    if memory_arg:
        mem_limit = int(memory_arg) * 1024 * 1024 * 1024
    else:
        mem_limit = 8 * 1024 * 1024 * 1024
    try:
        rsrc = resource.RLIMIT_VMEM
    except:
        rsrc = resource.RLIMIT_AS
    resource.setrlimit(rsrc, (mem_limit, mem_limit))


def load_initial_storage(initial_storage_file):
    if initial_storage_file:
        with open(initial_storage_file, "rb") as f:
            return {int(k, 16): int(v, 16) for k, v in json.load(f).items()}
    return {}


def validate_arguments(args):
    if not args.bytecode and not args.file:
        print("ERROR! Please provide a file or bytecode argument.", file=sys.stderr)
        sys.exit(-1)
    if args.tainting_type not in {"storage", "all", None}:
        print(
            "Invalid value for tainting type. Valid values are 'all' or 'storage'.",
            file=sys.stderr,
        )
        sys.exit(-1)


def process_file(args, initial_storage, logger, name):
    process = psutil.Process(os.getpid())
    mem = None
    jcount = None
    ULisworth = None
    DFisworth = None
    CFG_duration = None
    CFG_endmem = None
    isTimeout = False
    isMemoryError = False
    exception = None
    file_size = 0
    # 记录起始时间
    _start = time.time()
    signal.signal(signal.SIGALRM, handle_timeout)
    signal.alarm(timeout_seconds)
    # 记录起始内存
    startmem = process.memory_info().rss / (1024 * 1024)
    try:
        configure_memory_limits(args.memory)
        with open(args.file) as infile:
            inbuffer = infile.read().rstrip()
        if inbuffer.startswith("0x"):
            inbuffer = inbuffer[2:]
        file_size = os.path.getsize(args.file)
        code = bytes.fromhex(inbuffer)
        p = Project(code)
        CFG_endtime = time.time()
        CFG_endmem = process.memory_info().rss / (1024 * 1024) - startmem
        CFG_duration = CFG_endtime - _start
        res, mem, jcount, ULisworth, DFisworth = analysis(
            p, initial_storage=initial_storage
        )
    except TimeoutException as e:
        isTimeout = True
        gc.collect()
    except MemoryError as e:
        isMemoryError = True
        gc.collect()
    except Exception as e:
        exception = e
        gc.collect()
    finally:
        if CFG_endmem is None:
            CFG_endmem = None
        if mem is None:
            mem = process.memory_info().rss / (1024 * 1024) - startmem
        if jcount is None:
            jcount = p.cfg.jumpcount
        if ULisworth is None:
            ULisworth = None
        if DFisworth is None:
            DFisworth = None
        if CFG_duration is None:
            CFG_duration = None
        _end = time.time()
        signal.alarm(0)
        _duration = _end - _start
        logger.info(
            f"{name},{file_size},{isTimeout},{isMemoryError},{jcount},{CFG_endmem},{ULisworth},{DFisworth},{CFG_duration},{_duration},{mem},{exception}"
        )


# 0xedd4e9a8ca1e0d138c16cf205fbe54125d2090cf.code,False,False,9,None,None,None,8.678436279296875e-05,0.06797409057617188,183.30859375,None


def main(logger, name):
    print(f"Processing {name}")
    args = parse_arguments()
    validate_arguments(args)
    initial_storage = load_initial_storage(args.initial_storage_file)
    process_file(args, initial_storage, logger, name)


def process_code(full_path):
    logger = setuplogger()
    name = full_path.rsplit("/", 1)[-1]
    try:
        sys.argv = ["analyzer.py", "-f", full_path, "-b", "-m", "8"]
        main(logger, name)
    except Exception as e:
        gc.collect()


def available_memory():
    # 获取当前系统的可用内存
    return psutil.virtual_memory().available


def adjust_pool_size():
    min_memory_per_process = 8 * 1024 * 1024 * 1024
    available_mem = available_memory()
    print(f"Available memory: {available_mem/1024/1024/1024} GB")
    cpucount = multiprocessing.cpu_count()
    num = min(cpucount, int(available_mem / min_memory_per_process))
    print(
        f"Available CPU count: {cpucount},avaliable memory count: {int(available_mem / min_memory_per_process)}, set pool size to {num}"
    )
    num_processes = max(1, num)
    return num_processes


def batch_process():
    """
    批量处理文件，使用多进程
    """

    # 设置多个目录路径
    directories = [
        os.path.expanduser("/home/shuo/datasets/TN"),
        
    ]

    avamem = adjust_pool_size()
    print(f"Available pool: {avamem}")
    time.sleep(2)

    pool = Pool(avamem)
    print(pool._cache)

    filelist = []

    for directory_path in directories:
        for filename in os.listdir(directory_path):
            if filename.endswith(".code"):
                full_path = os.path.join(directory_path, filename)
                filelist.append(full_path)

    for path in filelist:
        pool.apply_async(process_code, (path,))
    pool.close()
    pool.join()


if __name__ == "__main__":
    batch_process()
    # process_code(
    #     "datasets/Ethereum/bytecode/0xedd4e9a8ca1e0d138c16cf205fbe54125d2090cf.code"
    # )
