#!/usr/bin/env python3
import argparse
import datetime
import json
import logging
import os
import stat
import sys
import time
from base64 import b64encode
from typing import Optional

import requests
import requests.utils

logger = logging.getLogger()
__author__ = 'Robert van Dijk'
__copyright__ = "Copyright 2022"
__credits__ = ['Robert van Dijk', 'Tim Laurence', 'Tobias Werth', 'Nicky Gerritsen']
__license__ = "GPL"
__version__ = "1.0.0"

# Reduce message to a single OK unless a checks fail.
no_ok = False

# Suppress performance data reporting
no_performance = False

OK_RC = 0
WARNING_RC = 1
CRITICAL_RC = 2
UNKNOWN_RC = 3

# These hold the final results
rc = -1
messages = []
performance_data = []

# Set the default base URL to submit to (optional). It can be overridden
# by the SUBMITBASEURL environment variable or the -u/--url argument.
baseurl = ''

# Use a specific API version, set to empty string for default
# or set to the version followed by a slash to use that version
api_version = ''

headers = {'user-agent': f'check_domjudge'}


def set_rc(new_rc):
    global rc
    rc = new_rc if new_rc > rc else rc


def ok(message):
    set_rc(OK_RC)
    messages.append('OK: ' + message)


def warning(message):
    set_rc(WARNING_RC)
    messages.append('WARNING: ' + message)


def critical(message):
    set_rc(CRITICAL_RC)
    messages.append('CRITICAL: ' + message)


def unknown(message):
    set_rc(UNKNOWN_RC)
    messages.append('UNKNOWN: ' + message)


def performance(label: str, value: float, UOM: str = '', warn: Optional[float] = None, crit: Optional[float] = None,
                min: Optional[float] = None, max: Optional[float] = None):
    p = f"'{label}'={value}{UOM}"
    if warn is not None:
        p += f";{warn}"
    else:
        p += ";"
    if crit is not None:
        p += f";{crit}"
    else:
        p += ";"
    if min is not None:
        p += f";{min}"
    else:
        p += ";"
    if max is not None:
        p += f";{max}"
    else:
        p += ";"
    performance_data.append(p)


def print_results():
    if no_ok:
        # Remove all the "OK"s
        filtered_messages = [message for message in messages if not message.startswith('OK: ')]
        if len(filtered_messages) == 0:
            messages_concat = 'OK'
        else:
            messages_concat = '; '.join(filtered_messages)

    else:
        messages_concat = '; '.join(messages)

    if no_performance or len(performance_data) == 0:
        print(messages_concat)
    else:
        perfdata_concat = ' '.join(performance_data)
        print(messages_concat + '|' + perfdata_concat)


def do_api_request(name: str):
    '''Perform an API call to the given endpoint and return its data.

    Parameters:
    name (str): the endpoint to call
    Returns:
    The endpoint contents.
    Raises:
    RuntimeError when the response is not JSON or the HTTP status code is non 2xx.
    '''

    if not baseurl:
        raise RuntimeError('No baseurl set')

    url = f'{baseurl}api/{api_version}{name}'

    logging.info(f'Connecting to {url}')

    try:
        response = requests.get(url, headers=headers)
    except requests.exceptions.RequestException as e:
        raise RuntimeError(e)

    if response.status_code >= 300:
        unknown(response.text)
        if response.status_code == 401:
            raise RuntimeError('Authentication failed.')
        else:
            raise RuntimeError(f'API request {name} failed (code {response.status_code}).')

    logging.debug(f"API call '{name}' returned:\n{response.text}")

    return json.loads(response.text)


def read_contests(active: bool = False) -> list:
    '''Read all contests from the API.

    Returns:
    The contests or None if an error occurred.
    '''

    try:
        data = do_api_request(f"contests?onlyActive={active}")
    except RuntimeError as e:
        unknown(str(e))
        return None

    if not isinstance(data, list):
        unknown("DOMjudge's API returned unexpected JSON data for endpoint 'contests'.")
        return None

    contests = []
    for contest in data:
        if ('id' not in contest
                or 'shortname' not in contest
                or not contest['id']
                or not contest['shortname']):
            unknown("DOMjudge's API returned unexpected JSON data for 'contests'.")
            return None
        contests.append(contest)

    logging.info(f'Read {len(contests)} contest(s) from the API.')
    return contests


def read_judgehosts() -> list:
    '''Read all judgehosts from the API.

    Returns:
    The judgehosts or None if an error occurred.
    '''

    try:
        data = do_api_request(f"judgehosts")
    except RuntimeError as e:
        unknown(str(e))
        return None

    if not isinstance(data, list):
        unknown("DOMjudge's API returned unexpected JSON data for endpoint 'judgehosts'.")
        return None

    judgehosts = []
    for judgehost in data:
        if ('id' not in judgehost
                or 'hostname' not in judgehost
                or 'enabled' not in judgehost
                or 'polltime' not in judgehost
                or 'hidden' not in judgehost):
            unknown("DOMjudge's API returned unexpected JSON data for 'contests'.")
            return None
        judgehosts.append(judgehost)

    logging.info(f'Read {len(judgehosts)} judgehost(s) from the API.')
    return judgehosts


def read_status() -> list:
    '''Read status from the API.

    Returns:
    The status or None if an error occurred.
    '''

    try:
        data = do_api_request(f"status")
    except RuntimeError as e:
        unknown(str(e))
        return None

    if not isinstance(data, list):
        unknown("DOMjudge's API returned unexpected JSON data for endpoint 'status'.")
        return None

    statuses = []
    for status in data:
        if ('num_submissions' not in status
                or 'num_queued' not in status
                or 'num_judging' not in status
                or 'cid' not in status):
            unknown("DOMjudge's API returned unexpected JSON data for 'contests'.")
            return None
        statuses.append(status)

    logging.info(f'Read {len(statuses)} status(es) from the API.')
    return statuses


if __name__ == '__main__':
    parser = argparse.ArgumentParser(prog='chech_domjudge.py')
    parser.add_argument('check', choices=['active_contests', 'judgehost_health', 'num_queue'])
    parser.add_argument('-H', '--host', action='store', dest='url', default=None, help='api url', required=True)
    parser.add_argument('-u', '--user', action='store', dest='user', default=None, help='api user', required=True)
    parser.add_argument('-p', '--password', action='store', dest='password', default=None, help='api password',
                        required=True)
    parser.add_argument('-w', '--warning', action='store', dest='warning', default=None,
                        help='waning value if applicable',
                        required=False, type=int)
    parser.add_argument('-c', '--critical', action='store', dest='critical', default=None,
                        help='critical value if applicable',
                        required=False, type=int)
    # no-ok
    parser.add_argument('--no-ok',
                        dest='no_ok',
                        action='store_true',
                        help='Make output terse suppressing OK messages. If all checks are OK return a single OK.')

    # no-performance
    parser.add_argument('--no-performance',
                        dest='no_performance',
                        action='store_true',
                        help='Suppress performance data. Reduces output when performance data is not being used.')

    args = parser.parse_args()

    baseurl = args.url
    # Make sure that baseurl terminates with a '/' for later concatenation.
    if baseurl and baseurl[-1:] != '/':
        baseurl += '/'

    userAndPass = b64encode(str.encode(f"{args.user}:{args.password}")).decode("ascii")
    headers['Authorization'] = f"Basic {userAndPass}"

    no_ok = args.no_ok

    no_performance = args.no_performance

    try:
        if args.check == 'active_contests':
            total = read_contests(active=False)
            active = read_contests(active=True)
            if len(active) > 1:
                critical(f"{len(active)} out of {len(total)} contests active.")
            elif len(active) < 1:
                warning(f"{len(active)} out of {len(total)} contests active.")
            else:
                ok(f"{len(active)} out of {len(total)} contests active.")
            performance(f"total contests", len(total), min=0)
            performance(f"active contests", len(active), min=0)

        if args.check == 'judgehost_health':
            judgehosts = read_judgehosts()
            for judgehost in judgehosts:
                if judgehost['hidden']:
                    continue
                if judgehost['polltime'] is None:
                    unknown(f"{judgehost['hostname']} never checked in")
                else:
                    polltime = datetime.datetime.fromtimestamp(int(float(judgehost['polltime'])))
                    reltime = datetime.datetime.now() - polltime
                    if args.critical is not None and reltime.total_seconds() >= args.critical:
                        critical(f"{judgehost['hostname']} last checked in {int(reltime.total_seconds())} seconds ago")
                    elif args.warning is not None and reltime.total_seconds() >= args.warning:
                        warning(f"{judgehost['hostname']} last checked in {int(reltime.total_seconds())} seconds ago")
                    else:
                        ok(f"{judgehost['hostname']} last checked in {int(reltime.total_seconds())} seconds ago")
                performance(f"{judgehost['hostname']} last check in", int(reltime.total_seconds()), min=0,
                            warn=args.warning, crit=args.critical, UOM='s')

        if args.check == 'num_queue':
            statuses = read_status()
            max_queue = 0
            for status in statuses:
                if args.critical is not None and status['num_queued'] >= args.critical:
                    critical(f"Contest {status['cid']} has a queue of {status['num_queued']}")
                elif args.warning is not None and status['num_queued'] >= args.warning:
                    warning(f"Contest {status['cid']} has a queue of {status['num_queued']}")
                else:
                    ok(f"Contest {status['cid']} has a queue of {status['num_queued']}")
                max_queue = max(max_queue, status['num_queued'])
            performance("num_queue", max_queue, min=0, warn=args.warning, crit=args.critical)

    except Exception as e:
        unknown(str(e))

    print_results()
    exit(rc)
