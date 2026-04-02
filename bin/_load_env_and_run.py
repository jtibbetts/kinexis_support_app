"""Load a KEY=VALUE env file (no shell interpretation) then exec the remaining args."""
import os
import sys

env_file = sys.argv[1]
args = sys.argv[2:]  # e.g. ['manage.py', 'shell']

with open(env_file) as f:
    for line in f:
        line = line.rstrip("\n")
        if line and not line.startswith("#") and "=" in line:
            k, v = line.split("=", 1)
            os.environ[k.strip()] = v

os.execvp(sys.executable, [sys.executable] + args)
