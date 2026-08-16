from bcc import BPF
import ctypes as ct
import os
import signal
import time
import subprocess

ebpf_c_code = """
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

struct event_data_t {
    u32 pid;
    u32 uid;
    char comm[16];
    char filename[256];
};

BPF_PERF_OUTPUT(events);

TRACEPOINT_PROBE(syscalls, sys_enter_execve) {
    struct event_data_t data = {};

    data.pid = bpf_get_current_pid_tgid() >> 32;
    data.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    bpf_probe_read_user_str(&data.filename, sizeof(data.filename), (void *)args->filename);

    events.perf_submit(args, &data, sizeof(data));
    return 0;
}
"""

class EventData(ct.Structure):
    _fields_ = [
        ("pid", ct.c_uint32),
        ("uid", ct.c_uint32),
        ("comm", ct.c_char * 16),
        ("filename", ct.c_char * 256),
    ]

b = BPF(text=ebpf_c_code)

print("=" * 85)
print("🛡️  eBPF Autonomous Incident Detection & Self-Healing Pipeline Active")
print("=" * 85)
print(f"{'PID':<8} {'COMM':<16} {'STATUS':<15} {'ACTION / REMEDIATION':<35}")
print("-" * 85)

def remediate_incident(pid, comm, filename):
    print(f"\n🚨 [ANOMALY DETECTED] Process '{comm}' (PID: {pid}) executed unauthorized target: '{filename}'")
    
    # Check if PID is still active and kill it
    killed = False
    try:
        os.kill(pid, signal.SIGKILL)
        print(f"⚡ [SELF-HEALING] Successfully terminated PID {pid} via SIGKILL! Incident mitigated.\n")
        killed = True
    except ProcessLookupError:
        pass

    # If the process spawned under Python interpreter, terminate any running rogue_worker instance
    if not killed:
        try:
            res = subprocess.run(["pkill", "-9", "-f", "rogue_worker"], capture_output=True)
            if res.returncode == 0:
                print(f"⚡ [SELF-HEALING] Terminated active background rogue worker via SIGKILL! Incident mitigated.\n")
            else:
                print(f"⚠️ Workload completed before remediation signal arrived.\n")
        except Exception as e:
            print(f"❌ Remediation failed: {e}\n")

def process_event(cpu, data, size):
    event = ct.cast(data, ct.POINTER(EventData)).contents
    pid = event.pid
    comm = event.comm.decode('utf-8', 'replace').strip('\x00')
    filename = event.filename.decode('utf-8', 'replace').strip('\x00')

    # Flag rogue workloads and unauthorized scripts
    if "rogue" in filename or "unauthorized" in filename or "rogue" in comm:
        remediate_incident(pid, comm, filename)
    else:
        print(f"{pid:<8} {comm:<16} {'🟢 NORMAL':<15} {filename:<35}")

b["events"].open_perf_buffer(process_event)

while True:
    try:
        b.perf_buffer_poll(timeout=100)
    except KeyboardInterrupt:
        print("\n🛑 Autonomous Detection Engine stopped.")
        break