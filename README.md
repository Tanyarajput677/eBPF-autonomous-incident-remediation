# eBPF-Powered Autonomous Incident Detection & Self-Healing Pipeline 
A low-overhead, kernel-space observability and autonomous incident remediation engine built using **eBPF (Extended Berkeley Packet Filter)** and **Python (BCC)**.
## Overview
Traditional microservice observability relies heavily on user-space sidecar proxies, which introduce significant latency and CPU/memory overhead. This pipeline attaches directly to Linux tracepoints (`sys_enter_execve`), streaming structured execution events via a high-performance BPF perf ring buffer to detect unauthorized workloads and autonomously dispatch `SIGKILL` remediation signals in real time.
##Architecture
1. **eBPF Kernel Probe (`collector.py`):** Hooks into the `syscalls:sys_enter_execve` tracepoint to capture binary execution metadata directly from kernel space.
2. **Ring Buffer Pipeline:** Passes structured C structs (`pid`, `uid`, `comm`, `filename`) to user space via BPF perf event maps.
3. **Autonomous Engine (`engine.py`):** Compares process execution paths against a baseline and terminates anomalous or unauthorized processes immediately using kernel-level signals.
## Prerequisites
- Linux Kernel 5.x / 6.x (or WSL 2 on Windows 11)
- BCC Toolchain (`bpfcc-tools`,`python3-bpfcc`,`libbpf-dev`)
- Python 3.10+
## Quickstart
### 1. Run the Telemetry Collector
```bash
sudo python3 collector.py
