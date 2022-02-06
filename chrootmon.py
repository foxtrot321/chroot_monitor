import sys
import os
from bcc import BPF


bppf = r"""

BPF_RINGBUF_OUTPUT(buffer,1 << 4);
struct event {
    u32 pid;
    char comm[128];
    char filename[128];
   
};

BPF_PERF_OUTPUT(events);

TRACEPOINT_PROBE(syscalls,sys_enter_chroot) {
    struct event event = {};
    event.pid=bpf_get_current_pid_tgid();

    bpf_probe_read_user_str(event.filename, sizeof(event.filename),args->filename);
    buffer.ringbuf_output(&event, sizeof(event),0);
    return 0;
    
}

"""
b = BPF(text=bppf)

def get_ppid(pid):
    try:
        with open("/proc/%d/status" % pid) as status:
            for line in status:
                if line.startswith("PPid:"):
                    return int(line.split()[1])
    except IOError:
        pass
    return 0


def get_pid_name(pid):
    with open("/proc/%d/cmdline" % pid) as status:
        for line in status:
            return line

def callback(ctx, data, size):
    event = b['buffer'].event(data)
    print("PID","FILENAME")
    s="------>Primary Process"
    print(event.pid,event.filename,s)
    if "container" in event.filename:
    	print(event.pid,event.filename)
    	#os.kill(event.pid,9)
    	return
    a=get_ppid(event.pid)
    c=get_pid_name(a)
    if "container" in c:
        print(a,c)
        #os.kill(a,9)
        return	
    d=get_ppid(a)
    e=get_pid_name(d)	  
    if "container" in e:
 	print(d,e)
 	#os.kill(d,9)    
        return
        
b['buffer'].open_ring_buffer(callback)
    
print("Printing logs, ctrl-c to exit.")

try:
    while 1:
        b.ring_buffer_poll()

except KeyboardInterrupt:
    sys.exit()
