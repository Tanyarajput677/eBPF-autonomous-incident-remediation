from bcc import BPF
ebpf_program="""
int hello_world(void *ctx){
bpf_trace_printk("[eBPF] Kernel intercept: sys_clone called!\\n");
return 0;
}
"""
b=BPF(text=ebpf_program)
b.attach_kprobe(event=b.get_syscall_fnname("clone"), fn_name="hello_world")
print("eBPF Kernel Probe active! Listening for new processes (sys_clone)... Press CTRL+C to exit.")
b.trace_print()
