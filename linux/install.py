#!/usr/bin/env python3
"""PrivetDNS: native Linux DoT with saved configuration and timed recovery."""
import argparse
import base64
import getpass
import grp
import ipaddress
import json
import os
from pathlib import Path
import pwd
import re
import shutil
import socket
import ssl
import struct
import subprocess
import sys
import time

STATE = Path('/var/lib/privetdns-native')
NM = Path('/etc/NetworkManager/conf.d/90-privetdns-native.conf')
RD = Path('/etc/systemd/resolved.conf.d/90-privetdns-native.conf')
RES = Path('/etc/resolv.conf')
STUB = '/run/systemd/resolve/stub-resolv.conf'
TIMER = 'privetdns-native-rollback'
SMART_IPS = ('31.76.30.138', '31.76.244.138')
SPLIT_SERVICE = 'privetdns-splitdns.service'
SPLIT_UNIT = Path('/etc/systemd/system') / SPLIT_SERVICE
SPLIT_DEST = Path('/opt/privetdns-splitdns')
FIELDS = ('ipv4.dns', 'ipv4.ignore-auto-dns', 'ipv4.dns-search', 'ipv6.dns', 'ipv6.ignore-auto-dns', 'ipv6.dns-search')
ENV = {**os.environ, 'LC_ALL': 'C', 'LANG': 'C'}


def run(*args, check=True):
    r = subprocess.run(args, capture_output=True, text=True, timeout=20, env=ENV)
    if check and r.returncode:
        # Arguments can contain a hostname credential. Do not echo arguments.
        raise RuntimeError('Ошибка команды ' + args[0] + ' (код ' + str(r.returncode) + ')')
    return r.stdout.rstrip('\n')


def profile(uuid):
    return {k: run('nmcli', '--escape', 'no', '-g', k, 'connection', 'show', uuid) for k in FIELDS}


def private(path, data, mode=0o600):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    with os.fdopen(fd, 'w') as f:
        f.write(data)


def dhcp_dns(interface):
    output = run('nmcli', '-f', 'DHCP4', 'device', 'show', interface)
    result = []
    for line in output.splitlines():
        if 'domain_name_servers' not in line or '=' not in line:
            continue
        for value in re.split(r'[\s,;]+', line.split('=', 1)[1].strip()):
            try:
                address = ipaddress.IPv4Address(value)
            except ipaddress.AddressValueError:
                continue
            if not (address.is_loopback or address.is_link_local or address.is_multicast or address.is_unspecified) and str(address) not in result:
                result.append(str(address))
    if not result:
        raise RuntimeError('Сеть не выдала ни одного IPv4 DNS для обычных доменов')
    return result


def split_unit():
    return ('# PrivetDNS managed split DNS\n[Unit]\nDescription=PrivetDNS local selective DNS proxy\nAfter=network-online.target\nWants=network-online.target\n'
            '[Service]\nType=simple\nUser=root\nGroup=root\n'
            'ExecStart=/usr/bin/python3 /opt/privetdns-splitdns/splitdns.py --config /var/lib/privetdns-native/splitdns.json\n'
            'Restart=on-failure\nRestartSec=2\nNoNewPrivileges=yes\nProtectSystem=strict\nProtectHome=yes\n'
            'PrivateTmp=yes\nPrivateDevices=yes\nProtectKernelTunables=yes\nProtectKernelModules=yes\n'
            'ProtectControlGroups=yes\nRestrictAddressFamilies=AF_INET AF_UNIX\nCapabilityBoundingSet=\nAmbientCapabilities=\n'
            '[Install]\nWantedBy=multi-user.target\n')


def snapshot_file(path):
    st = path.lstat()
    return {'link': os.readlink(path) if path.is_symlink() else None,
            'bytes': base64.b64encode(path.read_bytes()).decode(),
            'mode': st.st_mode & 0o777, 'uid': st.st_uid, 'gid': st.st_gid}


def replace_resolv(saved):
    # Only this exact absolute path is replaced; no caller-controlled target.
    if RES.is_dir():
        raise RuntimeError('resolv.conf стал каталогом; восстановление остановлено')
    temp = RES.with_name('.privetdns-resolv-restore')
    if temp.exists() or temp.is_symlink():
        raise RuntimeError('Временный файл восстановления уже существует')
    if saved['link'] is not None:
        temp.symlink_to(saved['link'])
        os.chown(temp, saved['uid'], saved['gid'], follow_symlinks=False)
    else:
        fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, saved['mode'])
        with os.fdopen(fd, 'wb') as f:
            f.write(base64.b64decode(saved['bytes']))
        os.chown(temp, saved['uid'], saved['gid'])
        os.chmod(temp, saved['mode'])
    os.replace(temp, RES)


def state():
    if STATE.is_symlink() or STATE.stat().st_uid != 0 or STATE.stat().st_mode & 0o077:
        raise RuntimeError('Небезопасная резервная папка')
    path = STATE / 'state.json'
    if path.is_symlink() or path.stat().st_uid != 0:
        raise RuntimeError('Небезопасный файл восстановления')
    s = json.loads(path.read_text())
    if not re.fullmatch(r'[a-fA-F0-9-]{36}', s['uuid']) or not re.fullmatch(r'[A-Za-z0-9_.:-]+', s['interface']):
        raise RuntimeError('Повреждённая резервная копия')
    if set(s['profile']) != set(FIELDS):
        raise RuntimeError('Неполная резервная копия')
    return s


def save_state(s):
    tmp = STATE / 'state.next'
    private(tmp, json.dumps(s, ensure_ascii=False))
    os.replace(tmp, STATE / 'state.json')


def cleanup_split_runtime():
    if SPLIT_UNIT.exists() or SPLIT_UNIT.is_symlink():
        if SPLIT_UNIT.is_symlink() or '# PrivetDNS managed split DNS' not in SPLIT_UNIT.read_text():
            raise RuntimeError('Служебный unit изменён другой программой')
        SPLIT_UNIT.unlink()
    if SPLIT_DEST.exists() or SPLIT_DEST.is_symlink():
        if SPLIT_DEST.is_symlink() or not SPLIT_DEST.is_dir() or SPLIT_DEST.stat().st_uid != 0:
            raise RuntimeError('Небезопасный каталог split-DNS')
        allowed = {'splitdns.py','smartdns-domains.txt'}
        children = list(SPLIT_DEST.iterdir())
        if any(child.name not in allowed or child.is_symlink() or not child.is_file() or child.stat().st_uid != 0 for child in children):
            raise RuntimeError('В каталоге split-DNS есть посторонние файлы')
        for child in children:
            child.unlink()
        SPLIT_DEST.rmdir()
    run('systemctl','daemon-reload')


def restore(automatic=False):
    s = state()
    if s.get('restored'):
        if not automatic:
            run('systemctl', 'stop', TIMER + '.timer', check=False)
        print('Прежние настройки уже восстановлены.')
        return
    errors = []
    try:
        run('systemctl', 'disable', '--now', SPLIT_SERVICE, check=False)
    except Exception as e:
        errors.append(str(e))
    for p in (NM, RD):
        try:
            if p.is_symlink():
                raise RuntimeError('Подмена файла конфигурации')
            if p.exists():
                if '# PrivetDNS native' not in p.read_text():
                    raise RuntimeError('Конфигурация изменена другой программой')
                p.unlink()
        except Exception as e:
            errors.append(str(e))
    if errors:
        raise RuntimeError('; '.join(errors))
    args = ['nmcli', 'connection', 'modify', s['uuid']]
    for k,v in s['profile'].items():
        args += [k,v]
    for command in (args, ['systemctl','reload','NetworkManager'],
                    ['nmcli','device','reapply',s['interface']], ['systemctl','restart','systemd-resolved']):
        try: run(*command)
        except Exception as e: errors.append(str(e))
    # NM's async rewrite must finish before restoring exact original bytes/link.
    time.sleep(2)
    replace_resolv(s['resolv'])
    if s['resolved_enabled'] != 'enabled':
        run('systemctl','disable','systemd-resolved.service')
        if s['resolved_enabled'] == 'enabled-runtime':
            run('systemctl','enable','--runtime','systemd-resolved.service')
    if profile(s['uuid']) != s['profile']:
        errors.append('Поля NetworkManager не совпадают с резервной копией')
    if errors:
        raise RuntimeError('Восстановление не завершено: '+ '; '.join(errors)+'. Backup: '+str(STATE))
    s['restored'] = True
    save_state(s)
    try:
        cleanup_split_runtime()
    except Exception as e:
        print('DNS восстановлен, но служебные файлы требуют проверки: '+str(e),file=sys.stderr)
    if not automatic:
        run('systemctl', 'stop', TIMER + '.timer', check=False)
    print('Прежний DNS восстановлен. Резервная копия сохранена: '+str(STATE))


def exact(sock, n):
    buf = bytearray()
    while len(buf)<n:
        block=sock.recv(n-len(buf))
        if not block: raise RuntimeError('DNS закрыл соединение')
        buf.extend(block)
    return bytes(buf)


def query(domain):
    return os.urandom(2)+bytes.fromhex('01000001000000000000')+b''.join(bytes([len(l)])+l.encode() for l in domain.split('.'))+bytes.fromhex('0000010001')


def verify_answer(q,a):
    if len(a)<12 or a[:2]!=q[:2] or not a[2]&128 or a[3]&15 or int.from_bytes(a[6:8],'big')<1:
        raise RuntimeError('DNS вернул ошибку или пустой ответ')


def check_remote(host):
    q=query('example.org')
    failures = 0
    for address in SMART_IPS:
        try:
            with socket.create_connection((address,853),timeout=8) as raw:
                with ssl.create_default_context().wrap_socket(raw,server_hostname=host) as sock:
                    sock.sendall(struct.pack('!H',len(q))+q)
                    n=struct.unpack('!H',exact(sock,2))[0]
                    if not 12<=n<=65535:raise RuntimeError('Неверный DNS ответ')
                    verify_answer(q,exact(sock,n))
                    return
        except (OSError, ssl.SSLError, RuntimeError):
            failures += 1
    if failures == len(SMART_IPS):
        raise RuntimeError('Обе защищённые DNS-точки недоступны')


def check_system(host):
    lines=run('resolvectl','dns').splitlines()
    if not lines or lines[0].strip()!='Global: 127.0.0.1:5300':
        raise RuntimeError('Не применился локальный split-DNS')
    if any(line.partition('):')[2].strip() for line in lines[1:]):
        raise RuntimeError('Другие интерфейсы продолжают выдавать DNS')
    if run('resolvectl','dnsovertls').splitlines()[0].strip() not in ('Global: no','Global: no/unsupported'):
        raise RuntimeError('Локальный DNS ошибочно помечен как удалённый TLS')
    run('resolvectl','flush-caches')
    for domain in ('example.org','gemini.google.com'):
        q=query(domain)
        with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as sock:
            sock.settimeout(8);sock.connect(('127.0.0.53',53));sock.send(q);a=sock.recv(65535)
        verify_answer(q,a)
        if domain=='gemini.google.com' and not any(socket.inet_aton(address) in a[12:] for address in SMART_IPS):
            raise RuntimeError('Gemini не получил Smart DNS ответ')
    run('getent','ahostsv4','example.org')


def install(host_stdin=False):
    for tool in ('nmcli','systemctl','systemd-run','resolvectl','ip','getent'):
        if not shutil.which(tool):raise RuntimeError('Не найдена команда '+tool)
    if STATE.exists() or STATE.is_symlink():
        s=state()
        if not s.get('restored'):raise RuntimeError('Установка уже есть: сначала запустите remove.sh')
        archive=Path(str(STATE)+'-archive-'+str(time.time_ns()))
        if STATE.resolve()!=Path('/var/lib/privetdns-native') or archive.exists():raise RuntimeError('Небезопасный путь архива')
        STATE.rename(archive)
    routes=json.loads(run('ip','-j','route','get',SMART_IPS[0]))
    interface=routes[0].get('dev','')
    if not re.fullmatch(r'[A-Za-z0-9_.:-]+',interface):raise RuntimeError('Не определён сетевой интерфейс')
    uuid=run('nmcli','-g','GENERAL.CON-UUID','device','show',interface)
    if not re.fullmatch(r'[a-fA-F0-9-]{36}',uuid):raise RuntimeError('Подключение не управляется NetworkManager')
    if run('systemctl','is-active','systemd-resolved')!='active':raise RuntimeError('Нужен работающий systemd-resolved')
    for row in run('nmcli','-t','-f','DEVICE,TYPE','device','status').splitlines():
        dev,kind=row.split(':',1)
        if dev!=interface and kind in ('tun','wireguard','vpn'):raise RuntimeError('Сначала отключите VPN')
    for path in (NM,RD):
        if path.exists() or path.is_symlink():raise RuntimeError('Уже существует конфиг PrivetDNS')
        if path.parent.exists() and any(path.parent.glob('*.conf')):raise RuntimeError('Есть сторонние DNS drop-in; требуется ручная настройка')
    for path,pattern in ((Path('/etc/systemd/resolved.conf'),r'^\s*(DNS|FallbackDNS|DNSOverTLS|Domains)\s*='),
                         (Path('/etc/NetworkManager/NetworkManager.conf'),r'^\s*(dns|rc-manager)\s*=')):
        if path.exists() and re.search(pattern,path.read_text(),re.M):raise RuntimeError('Существующая DNS политика: '+str(path))
    for p in (Path('/etc/NetworkManager/conf.d/90-privetdns-direct.conf'),Path('/etc/systemd/resolved.conf.d/90-privetdns-direct.conf'),Path('/etc/systemd/resolved.conf.d/90-privetdns-arch.conf')):
        if p.exists():raise RuntimeError('Сначала удалите активную старую установку')
    if SPLIT_UNIT.exists() or SPLIT_UNIT.is_symlink() or SPLIT_DEST.exists() or SPLIT_DEST.is_symlink():
        raise RuntimeError('Найдены файлы прошлой split-DNS установки; сначала завершите удаление')
    service_user=run('systemctl','show','systemd-resolved','-p','User','--value')
    service_group=run('systemctl','show','systemd-resolved','-p','Group','--value')
    account=pwd.getpwnam(service_user or 'root')
    gid=grp.getgrnam(service_group).gr_gid if service_group else account.pw_gid
    if not host_stdin and not sys.stdin.isatty():raise RuntimeError('Запустите из обычного терминала')
    host=(sys.stdin.readline(256) if host_stdin else
          getpass.getpass('Личное имя DoT из кабинета (ввод скрыт): ')).strip().lower().rstrip('.')
    if not re.fullmatch(r'[a-z2-7]{32}\.dot\.privetdns\.ru',host):raise RuntimeError('Нужно DoT имя, не HTTPS ссылка')
    check_remote(host)
    ordinary_dns = dhcp_dns(interface)
    os.umask(0o077);STATE.mkdir(mode=0o700)
    s={'uuid':uuid,'interface':interface,'profile':profile(uuid),'resolv':snapshot_file(RES),
       'resolved_enabled':run('systemctl','is-enabled','systemd-resolved',check=False),'restored':False}
    save_state(s)
    helper=STATE/'recovery.py';shutil.copyfile(Path(__file__).resolve(),helper);helper.chmod(0o700)
    run('systemd-run','--unit='+TIMER,'--on-active=300s',sys.executable,str(helper),'recover')
    try:
        for directory in (NM.parent, RD.parent):
            if directory.is_symlink(): raise RuntimeError('Подмена каталога конфигурации')
            if not directory.exists():
                directory.mkdir(parents=True, mode=0o755)
                directory.chmod(0o755)
            if not directory.stat().st_mode & 0o001:
                raise RuntimeError('Служба не может пройти в каталог '+str(directory))
        private(NM,'# PrivetDNS native\n[main]\ndns=none\nrc-manager=unmanaged\n')
        private(RD,'# PrivetDNS native\n[Resolve]\nDNS=127.0.0.1:5300\nDomains=~.\nFallbackDNS=\nDNSOverTLS=no\nDNSStubListener=yes\nLLMNR=no\nMulticastDNS=no\n',0o640)
        os.chown(RD,0,gid);os.chmod(RD,0o640) # daemon MUST be able to read it
        source = Path(__file__).resolve().parent
        SPLIT_DEST.mkdir(mode=0o755)
        for name in ('splitdns.py','smartdns-domains.txt'):
            src = source / name
            if not src.is_file() or src.is_symlink():
                raise RuntimeError('В архиве отсутствует '+name)
            shutil.copyfile(src, SPLIT_DEST / name)
            (SPLIT_DEST / name).chmod(0o644)
        private(STATE/'splitdns.json',json.dumps({'personal_sni':host,'dot_ips':SMART_IPS,
            'dhcp_dns':ordinary_dns,'listen_port':5300,
            'domains_file':str(SPLIT_DEST/'smartdns-domains.txt')}))
        private(SPLIT_UNIT,split_unit(),0o644)
        run('systemctl','daemon-reload')
        run('systemctl','enable','--now',SPLIT_SERVICE)
        run('nmcli','connection','modify',uuid,'ipv4.dns','','ipv6.dns','','ipv4.dns-search','','ipv6.dns-search','','ipv4.ignore-auto-dns','yes','ipv6.ignore-auto-dns','yes')
        run('systemctl','reload','NetworkManager')
        run('nmcli','device','reapply',interface)
        # Symlink BEFORE restart: prevent foreign resolv.conf from being imported.
        if RES.is_dir():raise RuntimeError('Неожиданный каталог resolv.conf')
        RES.unlink();RES.symlink_to(STUB)
        run('systemctl','enable','systemd-resolved')
        run('systemctl','restart','systemd-resolved')
        check_system(host)
        run('systemctl','stop',TIMER+'.timer')
        print('PrivetDNS split-DNS установлен. Обычные сайты используют DNS сети; выбранные домены — защищённый Smart DNS.')
        print('Для удаления: sudo bash remove.sh')
    except BaseException:
        print('Установка прервана. Возвращаю прежний DNS...',file=sys.stderr)
        try: restore()
        except Exception:
            print('Автооткат не завершён. Запустите sudo python3 '+str(helper)+' recover; копия сохранена.',file=sys.stderr)
        raise


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('action',choices=('install','remove','recover'));parser.add_argument('--host-stdin',action='store_true');opts=parser.parse_args()
    if opts.host_stdin and opts.action!='install':raise RuntimeError('--host-stdin работает только при установке')
    if os.geteuid()!=0:raise RuntimeError('Нужен sudo')
    if opts.action=='install':install(opts.host_stdin)
    else:restore(opts.action=='recover')

if __name__=='__main__':
    try:main()
    except (Exception,KeyboardInterrupt) as e:
        print('Ошибка: '+str(e),file=sys.stderr);sys.exit(1)
