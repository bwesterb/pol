""" Terminal progressbars. """

import sys
import math
import time
import datetime
import collections

# Represents probablistic progress
# Example: tossing an unfair coin until we see heads
# `n`   number of tosses so far
# `n5`  number of tosses required such that on average 5% is done
# `n50` number of tosses required such that on average 50% is done
# `n95` number of tosses required such that on average 95% is done
# `p`   chance that we are done exactly after `n` tosses

prob_progress = collections.namedtuple('prob_progress',
                                ('n', 'n5', 'n50', 'n95', 'p'))

def coin(p, n):
    """ Returns prob_progress tuple for an unfair coin with chance p """
    cp = 1 - (1 - p) ** (n+1)
    n5 = math.log(1 - 0.05, 1 - p)
    n50 = math.log(1 - 0.5, 1 - p)
    n95 = math.log(1 - 0.95, 1 - p)
    return prob_progress(n, n5, n50, n95, cp)

class ProgressBar(object):
    """ Terminal progress bar accepting floats from the unit interval."""
    def __init__(self):
        raise NotImplementedError
    def __call__(self, value):
        raise NotImplementedError
    def start(self):
        raise NotImplementedError
    def end(self):
        raise NotImplementedError
    def __enter__(self):
        self.start()
        return self
    def __exit__(self, type, value, traceback):
        self.end()

class ProbablisticProgressBar(ProgressBar):
    """ Terminal progress bar accepting prob_progress tuples """
    def __init__(self):
        pass
    def __call__(self, value):
        time_elapsed = time.time() - self.start_time
        speed = value.n / time_elapsed if time_elapsed else None
        t95 = int(max(value.n95 - value.n, 0) / speed) if speed else None
        t50 = int(max(value.n50 - value.n, 0) / speed) if speed else None
        t5 = int(max(value.n5 - value.n, 0) / speed) if speed else None
        width = 80 # TODO
        p95 = int(min(value.n / value.n95, 1) * (width-2))
        p50 = int(min(value.n / value.n50, 1) * (width-2))
        p5 = int(min(value.n / value.n5, 1) * (width-2))
        b95 = p95
        b50 = p50 - p95
        b5 = p5 - p50
        s = width - 2 - p5
        sys.stdout.write('\033[1G')
        sys.stdout.write('['+'#'*b95 + '='*b50 + '-'*b5+' '*s+']')
        sys.stdout.write('\n%5s tried, %5.1f/s %5.1f%%  %8s %8s %8s\033[1A' % (
                    value.n, speed, value.p*100,
                        datetime.timedelta(0, t5) if t5 else '',
                        datetime.timedelta(0, t50) if t50 else '',
                        datetime.timedelta(0, t95) if t95 else ''))
        sys.stdout.flush()
    def start(self):
        self.start_time = time.time()
    def end(self):
        print
        print

if __name__ == '__main__':
    with ProbablisticProgressBar() as p:
        import time
        for i in xrange(1000):
            p(coin(0.005, i))
            time.sleep(0.1)
