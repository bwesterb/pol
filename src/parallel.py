""" Extensions to Python's multiprocessing. """

import time
import Queue
import threading
import multiprocessing

def parallel_map(func, seq, args=None, kwargs=None, chunk_size=1,
                        nworkers=None, progress=None, progress_interval=0.1,
                        initializer=None, use_threads=False):
    """ Similar to map, but executes in parallel.

            parallel_map(f, seq, args, kwargs)

        gives the same result as

            [f(x, *args, **kwargs) for x in seq]

            `nworkers`  number of workers to spawn
            `chunk_size`    number of elements to hand to a thread at the
                        same time.
            `progress`  a function to periodically call with the number of
                        elements of seq already mapped
            `progress_interval`     the approximate time interval to call
                        the `progress` function
            `initializer`           called in each worker process when spawn,
                        with (args, kwargs) as arguments.  `initializer`
                        may change args, kwargs.
            `use_threads`   specifies to use threads instead of processes. """
    # Shortcut for when there is only one chunk:
    if args is None:
        args = ()
    if kwargs is None:
        kwargs = {}
    if len(seq) <= chunk_size:
        if initializer is not None:
            initializer(args, kwargs)
        return  [func(x, *args, **kwargs) for x in seq]
    # We got more than one chunk --- we will need workers:
    def worker(c_func, c_args, c_kwargs, c_input, c_output, c_initializer):
        try:
            if c_initializer is not None:
                c_initializer(c_args, c_kwargs)
            while True:
                p = c_input.get()
                if p is None:
                    break
                i, xs = p
                ys = []
                for x in xs:
                    ys.append(c_func(x, *c_args, **c_kwargs))
                c_output.put((i, ys))
        except KeyboardInterrupt:
            pass
    if nworkers is None:
        nworkers = multiprocessing.cpu_count()
    p_input = multiprocessing.Queue()
    p_output = multiprocessing.Queue()
    processes = []
    N = len(seq)
    n = 0
    ret = [None]*N
    constr = threading.Thread if use_threads else multiprocessing.Process
    try:
        for i in xrange(nworkers):
            process = constr(target=worker, args=(func, args, kwargs, p_output,
                                                    p_input, initializer))
            processes.append(process)
            process.start()
        # Add the elements to be mapped to the queue
        for i in xrange(0, N, chunk_size):
            p_output.put((i, seq[i:i+chunk_size]))
        # and after that sentinels to signal the end
        # of the queue, one for each worker
        for i in xrange(nworkers):
            p_output.put(None)
        next_update = (time.time() + progress_interval
                            if progress else float('inf'))
        while n < N:
            i, ys = p_input.get()
            ret[i:i+len(ys)] = ys
            n += len(ys)
            if time.time() > next_update:
                next_update = time.time() + progress_interval
                progress(n)
    except KeyboardInterrupt:
        for process in processes:
            process.terminate()
        raise
    return ret

def parallel_try(func, args=None, kwargs=None, nworkers=None, progress=None,
                        progress_interval=0.1, update_interval=0.05,
                        initializer=None, join=True, use_threads=False):
    """ Execute `func` in parallel until it returns a value.
        Return that value.
        
            `func`      the function to call
            `args`      the arguments to `func`
            `kwargs`    the keyword arguments to `func`
            `nworkers`  the number of worker processes (/threads) to use
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
            `join`      specifies whether to wait for all threads to finish
            `use_threads`   specifies to use threads instead of processes. """
    def worker(c_func, c_args, c_kwargs, c_lock, c_done, c_output, c_counter,
                        c_initializer):
        try:
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
        except KeyboardInterrupt:
            pass
    if args is None:
        args = ()
    if kwargs is None:
        kwargs = {}
    if nworkers is None:
        nworkers = multiprocessing.cpu_count()
    p_done = multiprocessing.Event()
    p_lock = multiprocessing.Lock()
    p_counter = multiprocessing.RawValue('i', 0)
    p_input = multiprocessing.Queue()
    processes = []
    constr = threading.Thread if use_threads else multiprocessing.Process
    try:
        for i in xrange(nworkers):
            process = constr(target=worker, args=(func, args, kwargs, p_lock,
                                        p_done, p_input, p_counter,
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
    except KeyboardInterrupt:
        for process in processes:
            process.terminate()
        raise
    return p_input.get()
