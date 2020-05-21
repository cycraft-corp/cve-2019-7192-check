#!/usr/bin/env python
# -*- coding: utf-8 -*-

from __future__ import print_function

try:
    import queue
except ImportError:
    import Queue as queue

import datetime
import re
import sys
import logging
import threading

try:
    import requests
    import requests
    from requests.packages.urllib3.exceptions import InsecureRequestWarning

    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
except ImportError:
    sys.stderr.write('Please run `pip install requests` and try again')
    sys.exit(1)

THREADS = 32
jobs = queue.Queue()
results = queue.Queue()
done = []
parse_version_date = re.compile(
    r'(\d+\.\d+\.\d+).(\d{8})', flags=re.MULTILINE).findall
abort = False


def result_items(filepath):
    with open(filepath, 'rt') as f:
        for line in f:
            try:
                parts = line.split()
                if len(parts) >= 2:
                    yield parts[0], parts[1]
            except Exception as e:
                logger.exception(e)


def main(filepath):
    global abort
    threads = [threading.Thread(target=check_for_vulnerabilities)
               for _ in range(THREADS)]

    for ip, port in result_items(filepath):
        jobs.put((ip, port))

    [t.start() for t in threads]

    while len(done) < THREADS:
        try:
            ip, port, result = results.get(timeout=1)
        except queue.Empty:
            continue
        except KeyboardInterrupt:
            abort = True
            logger.info('Aborting, please wait...')

        if result:
            print('[+] vulnerable: {ip}:{port}'.format(**locals()))
        else:
            print('[-] NOT vulnerable: {ip}:{port}'.format(**locals()))

    [t.join() for t in threads]
    return 0


def check_for_vulnerabilities():
    global abort
    while not jobs.empty() and not abort:
        try:
            ip, port = jobs.get(timeout=1)
            results.put((ip, port, is_vulnerable(ip, port)))
        except Exception as e:
            logger.exception(e)
    done.append(1)


def is_vulnerable(ip, port):
    try:
        return is_vulnerable_version_date(
            extract_version_date(get(ip, port, '/photo/editor.php')))
    except Exception:
        return False


def is_vulnerable_version_date(version_date):
    try:
        version, date = version_date
        if version.startswith('6.'):
            return is_version_smaller(version, '6.0.3')
        if version.startswith('5.7'):
            return is_version_smaller(version, '5.7.10')
        if version.startswith('5.4'):
            return is_version_smaller(version, '5.4.9')
        if version.startswith('5.2'):
            return is_version_smaller(version, '5.2.11')
        return is_date_earlier_than(date, '20190918')
    except Exception:
        pass
    return False


def extract_version_date(html):
    matches = parse_version_date(html)
    if not matches:
        raise Exception('Invalid response')
    return matches[0]


def is_version_smaller(v1, v2):
    return tuple(map(int, v1.split('.'))) < tuple(map(int, v2.split('.')))


def is_date_earlier_than(d1, d2):
    d1, d2 = [datetime.datetime.strptime(d, '%Y%m%d') for d in (d1, d2)]
    return d1 < d2


def get(ip, port, url):
    if port in ('443', '8443'):
        schemes = ('https', 'http')
    else:
        schemes = ('http', 'https')

    for scheme in schemes:
        try:
            resp = requests.get(
                '{scheme}://{ip}:{port}{url}'.format(
                    **locals()), verify=False, timeout=2)
            return resp.text
        except Exception:
            continue
    return ''


if __name__ == '__main__':
    if len(sys.argv) != 2:
        sys.stderr.write(
            'Usage: {0} /path/to/ip-port.txt\n\n'.format(sys.argv[0]))
        sys.stderr.write('Example ip-port.txt:\n')
        sys.stderr.write('1.2.3.4 8080\n')
        sys.stderr.write('2.3.4.5 8080\n')
        sys.exit(1)

    level = logging.INFO
    logger = logging.getLogger(__name__)
    stream_handler = logging.StreamHandler()
    formatter = logging.Formatter('%(asctime)s %(levelname)s: %(message)s')
    stream_handler.setFormatter(formatter)
    logger.addHandler(stream_handler)
    stream_handler.setLevel(level)
    logger.setLevel(level)

    sys.exit(main(sys.argv[1]))
