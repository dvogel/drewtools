#!/usr/bin/env python3

import os
import os.path
import sys
from datetime import datetime
from urllib.parse import urlparse

def main (args):
    output_filename = None
    cmd = "/usr/bin/wget"
    cmd_args = [cmd, "--no-use-server-timestamps"]

    if len(args) < 1:
        print("Please provide a URL to download")
        return 1

    if len(args) == 1:
        url_parts = urlparse(args[0])
        if url_parts.scheme == '' or url_parts.netloc == '':
            print("Could not parse URL:", args[0])
            return 1
        path_parts = url_parts.path.split('/')
        if len(path_parts) == 0 or path_parts[-1] == '':
            print("Could not determine filename to use from URL:", args[0])
            return 1
        output_filename = path_parts[-1]
        while os.path.exists(output_filename):
            output_basename, output_ext = os.path.splitext(output_filename)
            output_filename = "{}_{}.{}".format(output_basename, datetime.now().isoformat(), output_ext)
        cmd_args.append(args[0])
        cmd_args.append("-O")
        cmd_args.append(output_filename)

    if output_filename is not None:
        print("Downloading to", output_filename)
        os.execv(cmd, cmd_args)

if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

