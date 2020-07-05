#!/usr/bin/env python

import sys
if sys.version_info[0] < 3 or (sys.version_info[1] == 3
            and sys.version_info[1] < 6):
    sys.stderr.write("pol must be run with Python 3.6 or later (instead of %s)\n"
                        % '.'.join(map(str, sys.version_info)))
    sys.exit(-22)

import pol.cli

if __name__ == '__main__':
    sys.exit(pol.cli.entrypoint())
