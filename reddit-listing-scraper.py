#!/usr/bin/env python3
#
# Useful for scraping content linked to from reddit.
#
# USAGE: reddit-listing-scraper
#
# Expects URL to be a reddit listing URL. Extracts the subreddit name. Uses
# that to look up instructions in the .reddit-listing-scrapper file in the
# current directory. Here's an example instruction listing for downloading cute
# animal pics:
#
# aww:
#   - command: ensure-listing-json-url
#   - command: dl-json
#   - command: extract-json-value
#     json_pointer: /0/data/children/0/data/url
#   - command: exec
#     cmd: easywget

import copy
import os
import re
import sys

import jsonpointer
import requests
import yaml

from urllib.parse import urlparse

debug_flag = False
g_registers = {}

def disable_debugging():
    global debug_flag
    debug_flag = False

def enable_debugging():
    global debug_flag
    debug_flag = True

def debug(*args, **kwargs):
    global debug_flag
    if debug_flag == True:
        print(*args, **kwargs)

class ExecError(Exception):
    def __init__(self, *args):
        self.msg = args[0]
        super().__init__(*args)

def extract_subreddit_from_url(url):
    pattern = re.compile(r'http[s]?://(?:www.)?reddit.com/r/(.+?)/')
    m = pattern.match(url)
    if m:
        return m.group(1)

    pattern = re.compile(r'http[s]?://(?:www.)?reddit.com/(user/.+?)/(saved|upvoted)')
    m = pattern.match(url)
    if m:
        return m.group(1)

def get_registers():
    global g_registers
    return copy.copy(g_registers)

def dl_json(url):
    headers = {'user-agent': 'reddix-dev0/0.0.1'}
    resp = requests.get(url, headers=headers)
    if resp.status_code == 200:
        return resp.json()
    else:
        raise ExecError("Failed to download %s. Received %s response from server." % (url, resp.status_code))

def cmd_dl_json(_instr, value):
    return dl_json(value)

def dl_html(url):
    headers = {'user-agent': 'reddix-dev0/0.0.1'}
    resp = requests.get(url, headers=headers)
    if resp.status_code == 200:
        return resp.text
    else:
        raise ExecError("Failed to download %s. Received %s response from server." % (url, resp.status_code))

def cmd_dl_html(_instr, value):
    return dl_html(value)

def ensure_listing_json_url(url):
    if url.endswith('.json'):
        return url
    else:
        while len(url) > 1 and url.endswith('/'):
            url = url[0:-1]
        return "%s.json" % (url,)

def cmd_ensure_listing_json_url(_instr, value):
    return ensure_listing_json_url(value)

def cmd_extract_json_value(instr, value):
    try:
        extracted = jsonpointer.resolve_pointer(value, instr['json_pointer'])
        return extracted
    except jsonpointer.JsonPointerException:
        raise ExecError("Failed to resolve JSON pointer %s" % (instr['json_pointer'],))

def cmd_extract_regex_capture(instr, value):
    pattern = None
    try:
        pattern = re.compile(instr['pattern'], re.S)
    except (re.error, TypeError):
        raise ExecError("Failed to compile regex '%s'" % (instr['pattern']))

    m = pattern.match(value)
    if m:
        return m.group(1)
    else:
        raise ExecError("Failed to match '%s'" % (instr['pattern'],))

def cmd_exec(instr, value):
    args = [instr['cmd']]
    if 'args' in instr:
        rewritten_args = [arg.format(**get_registers(), value=value) for arg in instr['args']]
        args.extend(rewritten_args)
    else:
        args.append(str(value))
    os.execvp(instr['cmd'], args)

def cmd_load(instr, value):
    global g_registers
    return g_registers[instr['register']]

def cmd_regex_replace(instr, value):
    pattern = re.compile(instr['pattern'], re.S)
    substitution = instr['substitution']
    value = pattern.sub(substitution, value)
    return value

def cmd_require_media_file_url(instr, value):
    pattern = re.compile(r'http[s]://.+/.+.(avi|gif|gifv|jpg|mp4|png)')
    m = pattern.match(value)
    if m:
        return value

def cmd_store(instr, value):
    global g_registers
    g_registers[instr['register']] = value
    return value


VALID_COMMANDS = {
    #'reddit-login': cmd_reddit_login,
    'ensure-listing-json-url': cmd_ensure_listing_json_url,
    'dl-json': cmd_dl_json,
    'extract-json-value': cmd_extract_json_value,
    'extract-regex-capture': cmd_extract_regex_capture,
    'dl-html': cmd_dl_html,
    'exec': cmd_exec,
    'load': cmd_load,
    'regex_replace': cmd_regex_replace,
    'require-media-file-url': cmd_require_media_file_url,
    'store': cmd_store,
}

def process_options(args):
    options = {
        'debug': False
    }
    new_args = []
    for arg in args:
        if arg == "-d":
            options['debug'] = True
        else:
            new_args.append(arg)
    return (new_args, options)

def main(args):
    (args, options) = process_options(args)
    if options['debug']:
        enable_debugging()

    cfg = None
    with open('.reddit-listing-scraper') as fil:
        cfg = yaml.safe_load(fil.read())


    subreddit_name = extract_subreddit_from_url(args[0])
    debug("SUBREDDIT: %s" % (subreddit_name,))

    instructions = []
    try:
        instructions = cfg[subreddit_name]
    except KeyError:
        print("No instructions for subreddit: %s" % (subreddit_name,))
        print("Known subreddits:")
        for key in cfg:
            print("  - %s" % (key,))
        return 1
    value = args[0]
    try:
        for instr in instructions:
            debug("CURRENT VALUE: %s" % (str(value)[0:100],))
            cmd_name = instr['command']
            if cmd_name in VALID_COMMANDS:
                cmd_func = VALID_COMMANDS[cmd_name]
                value = cmd_func(instr, value)
            else:
                raise ExecError("No such command: %s" % (cmd_name,))
        return 0
    except ExecError as err:
        print(err.msg)
        return 1

if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

