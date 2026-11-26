"""Owner-only service catalog and non-executing Compose planner.

No network calls, shell commands, filesystem inspection or Docker access here.
The optional local installer revalidates all inputs independently.
"""
import ipaddress
import uuid
from pathlib import PurePosixPath
from urllib.parse import urlsplit

CATALOG = {
    'jellyfin': {'name': 'Jellyfin', 'description': 'Movies, anime and TV', 'port': 8096,
                 'image': 'docker.io/jellyfin/jellyfin:latest',
                 'volumes': {'config': '/config', 'cache': '/cache'}, 'library': '/media',
                 'docs': 'https://jellyfin.org/docs/general/installation/container/'},
    'kavita': {'name': 'Kavita', 'description': 'Manga, comics and books', 'port': 5000,
               'image': 'ghcr.io/kareadita/kavita:latest',
               'volumes': {'config': '/kavita/config'}, 'library': '/books',
               'docs': 'https://wiki.kavitareader.com/'},
    'uptime-kuma': {'name': 'Uptime Kuma', 'description': 'Service availability', 'port': 3001,
                    'image': 'docker.io/louislam/uptime-kuma:2',
                    'volumes': {'data': '/app/data'}, 'library': None,
                    'docs': 'https://github.com/louislam/uptime-kuma/wiki'},
}
PRIVATE = tuple(ipaddress.ip_network(x) for x in ('10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16'))
SETTING = 'integration_connections_v1'


def valid_url(value):
    if not isinstance(value, str) or not 1 <= len(value) <= 400:
        raise ValueError('Invalid service URL')
    if any(ch.isspace() or ord(ch) < 32 or ord(ch) == 127 for ch in value) or '\\' in value:
        raise ValueError('Invalid service URL')
    p = urlsplit(value)
    if p.scheme not in ('http', 'https') or not p.hostname or p.username is not None or p.password is not None or p.query or p.fragment:
        raise ValueError('Use an HTTP(S) address without credentials, query or fragment')
    if p.port is not None and not 1 <= p.port <= 65535:
        raise ValueError('Invalid port')
    # Browser links only: no server-side request, redirect or DNS resolution.
    return value


def normalize_connections(d):
    rows = d.get('connections')
    if not isinstance(rows, list) or len(rows) > 32:
        raise ValueError('Invalid connections')
    out, seen = [], set()
    for row in rows:
        if not isinstance(row, dict):
            raise ValueError('Invalid connection')
        kind, label = row.get('kind'), row.get('label')
        if not isinstance(kind, str) or kind not in CATALOG or not isinstance(label, str):
            raise ValueError('Unknown integration')
        label = label.strip()
        if not 1 <= len(label) <= 80 or any(ord(ch) < 32 or ord(ch) == 127 for ch in label):
            raise ValueError('Invalid label')
        address = valid_url(row.get('url'))
        key = (kind, address)
        if key in seen:
            raise ValueError('Duplicate connection')
        seen.add(key)
        out.append({'kind': kind, 'label': label, 'url': address})
    return out


def state():
    import core
    return {'catalog': CATALOG, 'connections': core.setting(SETTING, [])}


def save(d):
    import core
    rows = normalize_connections(d)
    core.set_setting(SETTING, rows)
    return {'catalog': CATALOG, 'connections': rows}


def library_path(value):
    if not isinstance(value, str) or len(value) > 512 or not value.startswith('/') or value.startswith('//'):
        raise ValueError('Use an absolute Linux media directory')
    if any(ord(ch) < 32 or ord(ch) == 127 or ch in '$\\:' for ch in value):
        raise ValueError('Unsupported directory characters')
    parts = value.split('/')[1:]
    if any(not p or p.startswith('.') for p in parts):
        raise ValueError('Use a specific media directory, without hidden or relative components')
    if parts[0] not in ('srv', 'mnt', 'media', 'home') or len(parts) < (3 if parts[0] == 'home' else 2):
        raise ValueError('Use a dedicated directory under /srv, /mnt, /media or /home')
    return str(PurePosixPath(value))


def validate_options(d):
    kind = d.get('kind')
    if not isinstance(kind, str) or kind not in CATALOG:
        raise ValueError('Unknown integration')
    item = CATALOG[kind]
    port = d.get('port', item['port'])
    if type(port) is not int or not 1024 <= port <= 65535:
        raise ValueError('Choose a host port between 1024 and 65535')
    bind = d.get('bind', '127.0.0.1')
    if not isinstance(bind, str):
        raise ValueError('Invalid bind address')
    addr = ipaddress.IPv4Address(bind)
    if addr != ipaddress.IPv4Address('127.0.0.1') and not any(addr in net for net in PRIVATE):
        raise ValueError('Use loopback or an RFC1918 address')
    restart = d.get('restart', True)
    if type(restart) is not bool:
        raise ValueError('Invalid restart option')
    library = d.get('library', '')
    if item['library']:
        library = library_path(library)
    elif library != '':
        raise ValueError('This service does not use a media directory')
    return {'kind': kind, 'bind': str(addr), 'port': port, 'library': library, 'restart': restart}


def plan(d):
    options = validate_options(d)
    kind, addr, port, library, restart = (options[k] for k in ('kind', 'bind', 'port', 'library', 'restart'))
    item = CATALOG[kind]
    volumes = [{'type': 'volume', 'source': name, 'target': dest} for name, dest in item['volumes'].items()]
    if library:
        volumes.append({'type': 'bind', 'source': library, 'target': item['library'],
                        'read_only': True, 'bind': {'create_host_path': False}})
    project = 'nexus-app-' + kind + '-' + uuid.uuid4().hex[:12]
    compose = {
        'name': project,
        'services': {kind: {
            'image': item['image'], 'restart': 'unless-stopped' if restart else 'no',
            'ports': [{'target': item['port'], 'published': str(port), 'host_ip': addr, 'protocol': 'tcp'}],
            'volumes': volumes, 'security_opt': ['no-new-privileges:true'],
            'logging': {'driver': 'json-file', 'options': {'max-size': '10m', 'max-file': '3'}},
        }},
        'volumes': {name: {} for name in item['volumes']},
    }
    return {'options': options, 'compose': compose, 'url': f'http://{addr}:{port}', 'libraryTarget': item['library'],
            'warnings': ['Plan only: no Docker actions have been executed.',
                         'Review the directory, permissions, port, firewall and image version on the host.',
                         'Image tags are mutable; pin an audited digest before production deployment.',
                         'Finish the application setup wizard. HTTP is not encrypted; keep it private.',
                         'LAN binding is not a firewall. Do not expose or forward the port to the Internet.']}
