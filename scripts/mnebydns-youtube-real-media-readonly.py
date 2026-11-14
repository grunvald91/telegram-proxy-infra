#!/usr/bin/env python3
"""Obtain a public CC test video's URL on the actual DE egress and test 128 KiB.

Use only temporary owner-only files. Never print signed URLs or raw errors.
No browser cookies, accounts, app data or server configuration are used.
"""
import json
import os
import pathlib
import subprocess
import sys
import urllib.parse

sys.dont_write_bytecode = True


def extract(root):
    sys.path.insert(0, str(next(root.glob('yt_dlp-*.whl'))))
    from yt_dlp import YoutubeDL
    messages = []

    class Log:
        def debug(self, message):
            pass

        def warning(self, message):
            messages.append(message)

        def error(self, message):
            messages.append(message)

    options = {'quiet': True, 'no_warnings': True, 'logger': Log(), 'cachedir': False,
               'skip_download': True, 'noplaylist': True, 'socket_timeout': 10,
               'retries': 0, 'extractor_retries': 0,
               'extractor_args': {'youtube': {'player_client': ['android_vr']}},
               'format': '18/best[protocol=https]/bestaudio[protocol=https]'}
    try:
        with YoutubeDL(options) as ydl:
            info = ydl.extract_info('https://www.youtube.com/watch?v=aqz-KE-bpKQ', download=False)
        url = info.get('url', '')
        parsed = urllib.parse.urlsplit(url)
        if parsed.scheme != 'https' or not parsed.hostname or not parsed.hostname.endswith('.googlevideo.com'):
            raise ValueError('no direct media URL')
        value = {'url': url, 'headers': info.get('http_headers', {}),
                 'format_id': info.get('format_id')}
        p = root / 'media.json'
        fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, 'w') as f:
            json.dump(value, f)
        print('DE_MEDIA_URL_FROM_DE_EGRESS=FOUND', flush=True)
        print('DE_MEDIA_FORMAT=' + str(info.get('format_id')), flush=True)
    except Exception as ex:
        text = ' '.join(messages + [str(ex)]).lower()
        reason = next((label for fragment, label in (
            ('sign in', 'LOGIN_REQUIRED'), ('po token', 'PO_TOKEN_REQUIRED'),
            ('not available', 'VIDEO_UNAVAILABLE'), ('timed out', 'TIMEOUT'),
            ('http error 403', 'HTTP_403'), ('no direct media', 'NO_DIRECT_MEDIA_URL'))
            if fragment in text), type(ex).__name__)
        print('DE_MEDIA_URL_FROM_DE_EGRESS=FAILED_' + reason, flush=True)


def probe(root, role):
    p = root / 'media.json'
    if not p.is_file():
        print(role + '_MEDIA_RANGE=SKIPPED_NO_URL', flush=True)
        return
    value = json.loads(p.read_text())
    url = value['url']
    host = urllib.parse.urlsplit(url).hostname
    assert host and host.endswith('.googlevideo.com')
    paths = [('loopback', '127.0.0.1')]
    paths += [('direct', None)] if role == 'DE' else [('wg_de', '10.66.77.1')]
    for label, ip in paths:
        args = ['curl', '-4', '--http1.1', '--noproxy', '*', '-sS', '--max-time', '18',
                '--connect-timeout', '5', '--range', '0-131071', '--max-filesize', '262144',
                '-o', '/dev/null', '-w', '%{http_code} %{size_download} %{time_total}']
        for name, data in value.get('headers', {}).items():
            if name.lower() in ('user-agent', 'accept', 'accept-language', 'origin'):
                args.extend(['-H', name + ': ' + data])
        if ip:
            args.extend(['--resolve', host + ':443:' + ip])
        # The signed URL remains in memory and owner-only files, never logs.
        args.append(url)
        try:
            r = subprocess.run(args, text=True, capture_output=True, timeout=23)
            print(role + '_MEDIA_RANGE_' + label + '=RC' + str(r.returncode) + ' ' + r.stdout[:90], flush=True)
        except subprocess.TimeoutExpired:
            print(role + '_MEDIA_RANGE_' + label + '=PROCESS_TIMEOUT', flush=True)


if __name__ == '__main__':
    phase, folder = sys.argv[1:3]
    root = pathlib.Path(folder)
    if phase == 'extract':
        extract(root)
    elif phase == 'probe' and sys.argv[3] in ('RU', 'DE'):
        probe(root, sys.argv[3])
    else:
        raise SystemExit('invalid mode')
