from bcc import BPF
import time

device = "ens192"
bpf = BPF(src_file="xdp_pf.c")
fn = bpf.load_func("tls_filter", BPF.XDP)
bpf.attach_xdp(device, fn, 0)

try:
    bpf.trace_print()
except KeyboardInterrupt:
    pass

bpf.remove_xdp(device, 0)
