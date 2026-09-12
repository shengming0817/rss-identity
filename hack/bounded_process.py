"""Bound fixture subprocesses and reap their process group; this is not a total CI deadline."""
import os
import signal
import subprocess
import time


def reap_process_group(process, *, grace=2):
    """Success requires both a waited child and disappearance of its owned PGID."""
    for sig in (None, signal.SIGTERM, signal.SIGKILL):
        deadline = time.monotonic() + grace
        try:
            if sig is not None:
                try: os.killpg(process.pid, sig)
                except ProcessLookupError: pass
            process.communicate(timeout=max(0, deadline - time.monotonic()))
            while True:
                try: os.killpg(process.pid, 0)
                except ProcessLookupError: return True
                except PermissionError: pass  # A disappearing group can transiently return EPERM on macOS.
                left = deadline - time.monotonic()
                if left <= 0: break
                time.sleep(min(.02, left))
        except (OSError, subprocess.TimeoutExpired, KeyboardInterrupt):
            continue
    return False

def run(command, *, timeout, termination_grace=5, **kwargs):
    check=kwargs.pop('check',False)
    capture=kwargs.pop('capture_output',False)
    if capture: kwargs.update(stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    data=kwargs.pop('input',None)
    process=subprocess.Popen(command,start_new_session=True,**kwargs)
    def stop():
        if not reap_process_group(process, grace=termination_grace):
            raise subprocess.TimeoutExpired("process_group_cleanup", 3 * termination_grace)
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
