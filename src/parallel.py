""" Extensions to Python's multiprocessing. """

import time
import multiprocessing

def parallel_try(func, args=None, kwargs=None, nthreads=None, progress=None,
                        progress_interval=0.1, update_interval=0.05,
                        initializer=None, join=True):
    """ Execute `func` in parallel until it returns a value.
        Return that value.
        
            `func`      the function to call
            `args`      the arguments to `func`
            `kwargs`    the keyword arguments to `func`
            `nthreads`  the number of threads to use
            `progress`  a function to periodically call with the number of
                        tries already performed
            `progress_interval`     the approximate time interval to call
                        the `progress` function
            `update_interval`       the approximate interval in which the
                        worker threads report their status --- a higher
                        values gives better performance, but worse latency
                        (if `join` is True)
            `initializer`           called in each worker process when spawn,
                        with (args, kwargs) as arguments.  `initializer`
                        may change args, kwargs.
            `join`      specifies whether to wait for all threads to finish """
    def worker(c_func, c_args, c_kwargs, c_lock, c_done, c_output, c_counter,
                        c_initializer):
        if c_initializer is not None:
            c_initializer(c_args, c_kwargs)
        last_update = time.time()
        iterations = 0
        while True:
            now = time.time()
            if now - last_update >  update_interval:
                last_update = now
                with c_lock:
                    if c_done.is_set():
                        return
                    c_counter.value += iterations
                iterations = 0
            ret = c_func(*c_args, **c_kwargs)
            iterations += 1
            if ret is None:
                continue
            with c_lock:
                if c_done.is_set():
                    return
                c_output.put(ret)
                c_done.set()
    if args is None:
        args = ()
    if kwargs is None:
        kwargs = {}
    if nthreads is None:
        nthreads = multiprocessing.cpu_count()
    p_done = multiprocessing.Event()
    p_lock = multiprocessing.Lock()
    p_counter = multiprocessing.RawValue('i', 0)
    p_input = multiprocessing.Queue()
    processes = []
    for i in xrange(nthreads):
        process = multiprocessing.Process(target=worker, args=(func, args,
                                kwargs, p_lock, p_done, p_input, p_counter,
                                initializer))
        processes.append(process)
        process.start()
    if progress is None:
        p_done.wait()
    else:
        while not p_done.is_set():
            p_done.wait(progress_interval)
            progress(p_counter.value)
    if join:
        for process in processes:
            process.join()
    return p_input.get()
