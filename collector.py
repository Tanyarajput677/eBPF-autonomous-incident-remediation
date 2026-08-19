from bcc import BPF
import ctypes as ct

# eBPF C program using explicit tracepoint macro
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

# Compile and load eBPF bytecode
b = BPF(text=ebpf_c_code)

print("=" * 80)
print(f"{'PID':<8} {'UID':<6} {'COMM':<16} {'FILENAME / EXECUTABLE':<40}")
print("=" * 80)

def process_event(cpu, data, size):
    event = ct.cast(data, ct.POINTER(EventData)).contents
    pid = event.pid
    uid = event.uid
    comm = event.comm.decode('utf-8', 'replace')
    filename = event.filename.decode('utf-8', 'replace')
    print(f"{pid:<8} {uid:<6} {comm:<16} {filename:<40}")

# Open buffer and poll events with non-blocking timeout
b["events"].open_perf_buffer(process_event)

while True:
    try:
        b.perf_buffer_poll(timeout=100)
    except KeyboardInterrupt:
        print("\n🛑 Telemetry collector stopped.")
        break
