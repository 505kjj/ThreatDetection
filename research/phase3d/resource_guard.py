"""Run one local CPU experiment inside a bounded Windows job."""

import argparse
import ctypes as ct
from ctypes import wintypes as win
import json
import os
from pathlib import Path
import subprocess
import sys
import time
import _winapi


GIB = 1024 ** 3
CPU_LIMIT = 2
MEMORY_TARGET = 6_000_000_000
MEMORY_STOP = 7_250_000_000
MEMORY_CEILING = 8_000_000_000
BELOW_NORMAL = 0x4000
POLL_SECONDS = 2
BUSY_SECONDS = 30
ENV_THREADS = {
    "OMP_NUM_THREADS": "2",
    "MKL_NUM_THREADS": "1",
    "OPENBLAS_NUM_THREADS": "1",
    "NUMEXPR_NUM_THREADS": "1",
    "BLIS_NUM_THREADS": "1",
    "ARROW_NUM_THREADS": "1",
    "RAYON_NUM_THREADS": "1",
    "CUDA_VISIBLE_DEVICES": "-1",
    "THREAT_PHASE3D_GUARDED": "1",
}


class BasicLimits(ct.Structure):
    _fields_ = [
        ("processTime", ct.c_int64), ("jobTime", ct.c_int64), ("flags", win.DWORD),
        ("minWorkingSet", ct.c_size_t), ("maxWorkingSet", ct.c_size_t),
        ("activeProcesses", win.DWORD), ("affinity", ct.c_size_t),
        ("priority", win.DWORD), ("scheduling", win.DWORD),
    ]


class IoCounters(ct.Structure):
    _fields_ = [(name, ct.c_uint64) for name in (
        "readOperations", "writeOperations", "otherOperations",
        "readBytes", "writeBytes", "otherBytes",
    )]


class ExtendedLimits(ct.Structure):
    _fields_ = [
        ("basic", BasicLimits), ("io", IoCounters),
        ("processMemoryLimit", ct.c_size_t), ("jobMemoryLimit", ct.c_size_t),
        ("peakProcessMemory", ct.c_size_t), ("peakJobMemory", ct.c_size_t),
    ]


class Accounting(ct.Structure):
    _fields_ = [
        ("userTime", ct.c_int64), ("kernelTime", ct.c_int64),
        ("periodUserTime", ct.c_int64), ("periodKernelTime", ct.c_int64),
        ("pageFaults", win.DWORD), ("processes", win.DWORD),
        ("active", win.DWORD), ("terminated", win.DWORD),
    ]


def win_api():
    kernel = ct.WinDLL("kernel32", use_last_error=True)
    size_pointer = ct.POINTER(ct.c_size_t)
    time_pointer = ct.POINTER(win.FILETIME)
    signatures = {
        "CreateMutexW": (win.HANDLE, [ct.c_void_p, win.BOOL, win.LPCWSTR]),
        "CreateJobObjectW": (win.HANDLE, [ct.c_void_p, win.LPCWSTR]),
        "CloseHandle": (win.BOOL, [win.HANDLE]),
        "ResumeThread": (win.DWORD, [win.HANDLE]),
        "GetCurrentProcess": (win.HANDLE, []),
        "GetProcessAffinityMask": (win.BOOL, [win.HANDLE, size_pointer, size_pointer]),
        "SetProcessAffinityMask": (win.BOOL, [win.HANDLE, ct.c_size_t]),
        "SetPriorityClass": (win.BOOL, [win.HANDLE, win.DWORD]),
        "SetInformationJobObject": (win.BOOL, [win.HANDLE, ct.c_int, ct.c_void_p, win.DWORD]),
        "QueryInformationJobObject": (win.BOOL, [win.HANDLE, ct.c_int, ct.c_void_p, win.DWORD, ct.c_void_p]),
        "AssignProcessToJobObject": (win.BOOL, [win.HANDLE, win.HANDLE]),
        "TerminateJobObject": (win.BOOL, [win.HANDLE, win.UINT]),
        "GetSystemTimes": (win.BOOL, [time_pointer, time_pointer, time_pointer]),
    }
    for name, (result, arguments) in signatures.items():
        call = getattr(kernel, name)
        call.restype = result
        call.argtypes = arguments
    return kernel


def checked(value):
    if not value:
        raise ct.WinError(ct.get_last_error())
    return value


def affinity_subset(mask):
    result = 0
    for _ in range(CPU_LIMIT):
        next_bit = mask & -mask
        result |= next_bit
        mask -= next_bit
    if not result:
        raise ValueError("The host has no eligible CPUs")
    return result


def clock_ticks(kernel):
    idle, system, user = win.FILETIME(), win.FILETIME(), win.FILETIME()
    checked(kernel.GetSystemTimes(ct.byref(idle), ct.byref(system), ct.byref(user)))

    def ticks(value):
        return (value.dwHighDateTime << 32) | value.dwLowDateTime

    return ticks(idle), ticks(system) + ticks(user)


def percent_busy(before, now):
    elapsed = now[1] - before[1]
    if elapsed <= 0:
        return 0.0
    return (1 - (now[0] - before[0]) / elapsed) * 100


def job_value(kernel, handle, info_class, value):
    checked(kernel.QueryInformationJobObject(handle, info_class, ct.byref(value), ct.sizeof(value), None))
    return value


def stop_reason(peak_commit, busy_seconds):
    if peak_commit >= MEMORY_STOP:
        return "memory-approaching-ceiling"
    if busy_seconds >= BUSY_SECONDS:
        return "sustained-host-cpu-above-50-percent"
    return None


def monitor(kernel, job, process):
    prior = clock_ticks(kernel)
    started = last = time.monotonic()
    busy_seconds = 0.0
    host_samples = []
    reason = None
    peak = 0
    while _winapi.WaitForSingleObject(process, POLL_SECONDS * 1000) == _winapi.WAIT_TIMEOUT:
        now = time.monotonic()
        current = clock_ticks(kernel)
        host_cpu = percent_busy(prior, current)
        host_samples.append(host_cpu)
        busy_seconds = busy_seconds + (now - last) if host_cpu > 50 else 0.0
        peak = job_value(kernel, job, 9, ExtendedLimits()).peakJobMemory
        reason = stop_reason(peak, busy_seconds)
        if reason:
            checked(kernel.TerminateJobObject(job, 75))
            break
        prior, last = current, now
    _winapi.WaitForSingleObject(process, _winapi.INFINITE)
    exit_code = _winapi.GetExitCodeProcess(process)
    peak = max(peak, job_value(kernel, job, 9, ExtendedLimits()).peakJobMemory)
    accounting = job_value(kernel, job, 1, Accounting())
    violations = []
    if peak > MEMORY_TARGET:
        violations.append("6-GB-target-exceeded")
    if peak >= MEMORY_CEILING:
        violations.append("8-GB-ceiling-reached")
    if reason:
        violations.append(reason)
    report = {
        "exitCode": exit_code, "stopReason": reason, "resourceViolations": violations,
        "wallSeconds": time.monotonic() - started,
        "jobCpuSeconds": (accounting.userTime + accounting.kernelTime) / 10_000_000,
        "peakJobCommitBytes": peak, "hostCpuMaxPercent": max(host_samples, default=None),
        "hostCpuMeanPercent": sum(host_samples) / len(host_samples) if host_samples else None,
        "cpuSamples": len(host_samples), "samplesAbove30Percent": sum(n > 30 for n in host_samples),
    }
    return report


def run(command):
    kernel = win_api()
    current = kernel.GetCurrentProcess()
    eligible, machine = ct.c_size_t(), ct.c_size_t()
    checked(kernel.GetProcessAffinityMask(current, ct.byref(eligible), ct.byref(machine)))
    affinity = affinity_subset(eligible.value)
    checked(kernel.SetProcessAffinityMask(current, affinity))
    checked(kernel.SetPriorityClass(current, BELOW_NORMAL))
    lock = checked(kernel.CreateMutexW(None, True, r"Local\ThreatDetectionPhase3D"))
    if ct.get_last_error() == 183:
        kernel.CloseHandle(lock)
        raise RuntimeError("Another Phase 3D experiment is already active")
    job = None
    process = thread = None
    assigned = False
    try:
        job = checked(kernel.CreateJobObjectW(None, None))
        limits = ExtendedLimits()
        # Affinity, priority class, job commit ceiling, and kill-on-job-close.
        limits.basic.flags = 0x10 | 0x20 | 0x200 | 0x2000
        limits.basic.affinity = affinity
        limits.basic.priority = BELOW_NORMAL
        limits.jobMemoryLimit = MEMORY_CEILING
        checked(kernel.SetInformationJobObject(job, 9, ct.byref(limits), ct.sizeof(limits)))
        # Suspend before assignment so a Python launcher cannot spawn outside the job.
        create_suspended = 0x4
        process, thread, _, _ = _winapi.CreateProcess(
            None, subprocess.list2cmdline(command), None, None, True,
            create_suspended | BELOW_NORMAL, os.environ | ENV_THREADS, None, subprocess.STARTUPINFO(),
        )
        checked(kernel.AssignProcessToJobObject(job, process))
        assigned = True
        if kernel.ResumeThread(thread) == 0xFFFFFFFF:
            raise ct.WinError(ct.get_last_error())
        report = monitor(kernel, job, process)
        return report | {"logicalCpuAffinityCount": affinity.bit_count(), "jobCommitLimitBytes": MEMORY_CEILING}
    finally:
        if process:
            if assigned:
                kernel.TerminateJobObject(job, 75)
            else:
                _winapi.TerminateProcess(process, 75)
            _winapi.WaitForSingleObject(process, _winapi.INFINITE)
            _winapi.CloseHandle(process)
            _winapi.CloseHandle(thread)
        if job:
            kernel.CloseHandle(job)
        kernel.CloseHandle(lock)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--metrics", type=Path, required=True)
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    if sys.platform != "win32" or len(args.command) < 2 or args.command[0] != "--":
        parser.error("Use Windows and provide a worker command after --")
    metrics = args.metrics.resolve()
    repo = Path(__file__).resolve().parents[2]
    if metrics.is_relative_to(repo) or not metrics.parent.is_dir() or metrics.exists():
        parser.error("Use a new metrics file in an existing private directory outside Git")
    try:
        report = run(args.command[1:])
    except (OSError, ValueError, RuntimeError) as error:
        print(f"Resource guard refused the worker: {error}", file=sys.stderr)
        return 75
    temp = metrics.with_suffix(".tmp")
    with temp.open("x", encoding="utf-8") as stream:
        json.dump(report, stream, indent=2)
    temp.replace(metrics)
    print(json.dumps(report), flush=True)
    return report["exitCode"]


if __name__ == "__main__":
    raise SystemExit(main())
