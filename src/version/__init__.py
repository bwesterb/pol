#!/usr/bin/env python

import sys
import os.path
import subprocess
import pkg_resources

def get_version():
    git_version = None
    release_version = None

    # Are we frozen?  Then directly return RELEASE-VERSION
    if hasattr(sys, '_MEIPASS'):
        return open(os.path.join(sys._MEIPASS,
                                 'RELEASE-VERSION')).read().strip()

    # If not frozen, check the git version
    try:
        p = subprocess.Popen(['git', 'describe', '--abbrev=4'],
                  stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                  cwd=os.path.dirname(os.path.abspath(__file__)))
        p.stderr.close()
        if p.wait() != 0:
            raise OSError
        line = p.stdout.readlines()[0]
        git_version = line.strip()
    except OSError:
        pass

    # Directly return the pkg_resources version, if there is no git version
    if git_version is None:
        try:
            return pkg_resources.require('pol')[0].version
        except pkg_resources.DistributionNotFound:
            pass

    # In the other case check 
    release_version_path = os.path.join(os.path.dirname(
                os.path.abspath(__file__)), 'RELEASE-VERSION')

    try:
        release_version = open(release_version_path).read().strip()
    except IOError:
        release_version = None

    if git_version:
        if release_version != git_version:
            with open(release_version_path, 'w') as f:
                f.write(git_version)
        return git_version

    assert release_version

    return release_version

if __name__ == "__main__":
    print get_version()
