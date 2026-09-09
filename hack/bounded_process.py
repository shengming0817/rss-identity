"""Bound fixture subprocesses and reap their process group; this is not a total CI deadline."""
import os
import signal
import subprocess

def run(command, *, timeout, **kwargs):
    check=kwargs.pop('check',False)
    capture=kwargs.pop('capture_output',False)
    if capture: kwargs.update(stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    data=kwargs.pop('input',None)
    process=subprocess.Popen(command,start_new_session=True,**kwargs)
    def stop():
        # Descendants can hold pipes after the direct child exits; always address the owned group.
        try:os.killpg(process.pid,signal.SIGTERM)
        except ProcessLookupError:pass
        try:process.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            try:os.killpg(process.pid,signal.SIGKILL)
            except ProcessLookupError:pass
            process.communicate(timeout=5)
    previous=signal.getsignal(signal.SIGTERM)
    def terminate(signum,_frame):
        stop()
        raise SystemExit(128+signum)
    signal.signal(signal.SIGTERM,terminate)
    try:
        stdout,stderr=process.communicate(input=data,timeout=timeout)
        result=subprocess.CompletedProcess(command,process.returncode,stdout,stderr)
        if check:result.check_returncode()
        return result
    finally:
        signal.signal(signal.SIGTERM,previous)
        stop()
