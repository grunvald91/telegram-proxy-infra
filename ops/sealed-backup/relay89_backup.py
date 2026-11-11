#!/usr/bin/env python3
"""One-shot secrets/config backup. Only ciphertext leaves this process on stdout."""
import datetime, hashlib, io, json, os, pathlib, sqlite3, stat, subprocess, sys, tarfile, tempfile

ROOTS = ['/etc', '/opt', '/root', '/usr/local/etc', '/usr/local/libexec']
SKIP = {'.git', '.cache', 'node_modules', '.venv', 'venv', '__pycache__', 'go1.26.5', 'target', 'node-cache', '.npm', '.rustup', '.cargo', '.vscode-server'}

def digest(path):
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for block in iter(lambda: f.read(1024*1024), b''): h.update(block)
    return h.hexdigest()

def run():
    os.umask(0o077)
    here = pathlib.Path(__file__).resolve().parent
    for name in ('postgresql', 'mysql', 'redis'):
        p = pathlib.Path('/var/lib') / name
        if p.is_dir() and any(p.iterdir()):
            raise RuntimeError('Unsupported database storage requires a logical dump: '+name)
    roots = [pathlib.Path(p) for p in ROOTS if pathlib.Path(p).exists()]
    roots += [p for p in pathlib.Path('/var/lib').iterdir()
              if p.is_dir() and p.name.startswith(('mneby', 'telemt', 'mtproto', 'xray', 'hysteria', 'tproxy', 'zapret'))]
    outdir = pathlib.Path('/var/backups/mnebyvpn-sealed')
    outdir.mkdir(mode=0o700, exist_ok=True)
    stamp = datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%SZ')
    output = outdir / ('relay89-'+stamp+'.tar.gz.mnebak')
    manifest = {'format':1, 'created_utc':stamp, 'scope':'secrets/configuration and application state; not a disk image',
                'roots':[str(p) for p in roots], 'excluded_directory_names':sorted(SKIP), 'entries':[], 'sqlite_snapshots':[]}
    entries = []
    for root in roots:
        for folder, dirs, files in os.walk(root, followlinks=False):
            dirs[:] = sorted(d for d in dirs if d not in SKIP)
            for n in list(dirs):
                p = pathlib.Path(folder)/n
                if p.is_symlink(): entries.append(p); dirs.remove(n)
            for n in sorted(files):
                p = pathlib.Path(folder)/n
                if not stat.S_ISSOCK(p.lstat().st_mode): entries.append(p)
    entries = sorted(set(entries))
    with tempfile.TemporaryDirectory(prefix='mneby-backup-', dir='/var/tmp') as td:
        snapshots = {}
        for i, p in enumerate(entries):
            if not p.is_file() or p.is_symlink(): continue
            with p.open('rb') as f: magic = f.read(16)
            if magic != b'SQLite format 3\x00': continue
            target = pathlib.Path(td)/str(i)
            with sqlite3.connect(p.as_uri()+'?mode=ro',uri=True,timeout=30) as src:
                with sqlite3.connect(target) as dst:
                    src.backup(dst)
                    if dst.execute('PRAGMA integrity_check').fetchall() != [('ok',)]:
                        raise RuntimeError('SQLite snapshot integrity failure')
            snapshots[p] = target
            manifest['sqlite_snapshots'].append(str(p))
        proc = subprocess.Popen([sys.executable,str(here/'mnebyvpn_seal.py'),'encrypt',
            '--public-key',str(here/'mnebyvpn-recovery-public.pem'),'--output',str(output)],
            stdin=subprocess.PIPE,stdout=subprocess.DEVNULL)
        try:
            with tarfile.open(fileobj=proc.stdin,mode='w|gz',dereference=False) as tar:
                for p in entries:
                    # WAL files are represented by their consistent SQLite snapshot.
                    if any(str(p)==str(db)+s for db in snapshots for s in ('-wal','-shm','-journal')): continue
                    s = p.lstat()
                    name = 'rootfs/'+str(p).lstrip('/')
                    if stat.S_ISREG(s.st_mode):
                        source = snapshots.get(p,p)
                        before = source.stat()
                        h = digest(source)
                        info = tar.gettarinfo(str(source),arcname=name)
                        info.mode, info.uid, info.gid = stat.S_IMODE(s.st_mode),s.st_uid,s.st_gid
                        with source.open('rb') as f: tar.addfile(info,f)
                        after = source.stat()
                        if (before.st_size,before.st_mtime_ns,before.st_ino)!=(after.st_size,after.st_mtime_ns,after.st_ino) or digest(source)!=h:
                            raise RuntimeError('Source changed while archiving; retry a consistent snapshot')
                        manifest['entries'].append({'name':name,'size':info.size,'sha256':h,'mode':info.mode,'uid':info.uid,'gid':info.gid})
                    elif stat.S_ISLNK(s.st_mode):
                        tar.add(str(p),arcname=name,recursive=False)
                        manifest['entries'].append({'name':name,'symlink':os.readlink(p)})
                    else:
                        # Named pipes/device files cannot contain secret file bytes.
                        continue
                data=json.dumps(manifest,sort_keys=True).encode()
                info=tarfile.TarInfo('MANIFEST.json'); info.size=len(data); info.mode=0o600
                tar.addfile(info,io.BytesIO(data))
            proc.stdin.close()
            if proc.wait()!=0: raise RuntimeError('Encryption failed')
        except BaseException:
            proc.kill();proc.wait()
            raise
    print('server_ciphertext_sha256='+digest(output),file=sys.stderr,flush=True)
    print('server_ciphertext_bytes='+str(output.stat().st_size),file=sys.stderr,flush=True)
    print('server_file_count='+str(len(manifest['entries'])),file=sys.stderr,flush=True)
    print('server_sqlite_snapshot_count='+str(len(snapshots)),file=sys.stderr,flush=True)
    with output.open('rb') as f:
        for block in iter(lambda:f.read(1024*1024),b''):sys.stdout.buffer.write(block)
    sys.stdout.buffer.flush()

if __name__=='__main__':
    run()
