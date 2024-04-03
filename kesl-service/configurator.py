#
#
#
import os
import yaml
import shlex
import control
import validators
from pathlib import Path
from service_util import key_exists
from service_types import SecureString

service_config = dict([
    ('COMMON', dict([
        ('KRAS4D_PORT',     8085),
        ('KRAS4D_SQLPATH',  Path(__file__).parent.absolute().joinpath('data/scans.sqlite')),
        ('KRAS4D_TMPPATH',  Path(__file__).parent.absolute().joinpath('tmp/')),
        ('KRAS4D_CERTDIR',  Path(__file__).parent.absolute().joinpath('certificates/')),
        ('KRAS4D_KEYPATH',  Path(__file__).parent.absolute().joinpath('keys/')),
        ('KRAS4D_LOGPATH',  '/var/log/kaspersky/kesl-service/'),
        ('KRAS4D_LOGLEVEL', 'NOSET'),
        ('KRAS4D_LOGROTATE', None)
    ])),
    ('CONTROL', dict([
        ('KRAS4D_XAPIKEY',           None),
        ('KRAS4D_ACTIVATION',        None),
        ('KRAS4D_SCANOPTIONS',       None),
        ('KRAS4D_UPDATEOPTIONS',     None),
        ('KRAS4D_FORCEUPDATE',       True),
        ('KRAS4D_DETECTACTION',      'SKIP'),
        ('KRAS4D_SKIPIMAGEIFEXISTS', False),
        ('KRAS4D_GENERALTIMEOUT',    600),
        ('KRAS4D_UPDTASKTIMEOUT',    600)
    ])),
    ('HIDDEN', dict([
        ('KRAS4D_CFGNAME',  'kesl-service.config'),
        ('KRAS4D_CFGPATH',  Path(__file__).parent.absolute().joinpath('config/')),
        ('KRAS4D_PRVMODE',  False),
        ('KRAS4D_CRTDATA',  Path(__file__).parent.absolute().joinpath('tmp/cert_storage/')),
        ('KRAS4D_TDFORMAT', '%Y-%m-%dT%H:%M:%S.%f%SZ')
    ])),
    ('REPOSITORIES', {})
])

"""
common:
  port: 8085
  sqlpath: './data/scans.sqlite'
  tmppath: './tmp/'
  keypath: './keys/'
  certdir: './certificates/'
  logpath: '/var/log/kaspersky/kesl-service/'
  loglevel: 'debug'
control:
  xapikey: 0000
  activation: XXXX-XXXX-XXXX-XXXX or XXXX.key
  scanoptions: 'ScanArchives=yes'
  updateoptions: ''
  forceupdate: True
  detectaction: 'Skip'
  skipimageifexists: False
  generaltimeout: 600
  updtasktimeout: 600
repositories:
  cos-docker-reg.avp.ru:
    certificate: cert.pem
    credentials:
      user: user
      pass: password
"""


def check_privileged_mode():
    # runner = control.Control('podman')
    # _, code = runner.run_command('info')
    service_config['HIDDEN']['KRAS4D_PRVMODE'] = False


def set_var(section, values):
    for short_item in values:
        item = 'KRAS4D_' + short_item.upper()
        if item in service_config[section]:
            service_config[section][item] = values[short_item]
        else:
            print(f'unknown key {short_item} in section {section}')


def set_env(section):
    for item in service_config[section]:
        if item in os.environ:
            if type(service_config[section][item]) == bool:
                service_config[section][item] = os.environ[item].upper() in ['TRUE', 'YES', 'Y', 'ON']
            else:
                service_config[section][item] = os.environ[item]


def get_config():

    def copy_registry(source):
        for item in source:
            registry_name = item if item.startswith(('http://', 'https://')) else f'https://{item}'
            if not validators.url(registry_name):
                print(f'Invalid URL format for registry {registry_name}')
                continue
            tmp_user = SecureString(shlex.quote(source[item]['credentials']['user'])) if key_exists(
                source, item, 'credentials', 'user') else None
            tmp_pass = SecureString(shlex.quote(source[item]['credentials']['pass'])) if key_exists(
                source, item, 'credentials', 'pass') else None
            service_config['REPOSITORIES'].update({
                registry_name: {'credentials': {'user': tmp_user, 'pass': tmp_pass}}
            })

    config_path = os.environ['KRAS4D_CFGPATH'] if \
        'KRAS4D_CFGPATH' in os.environ else service_config['HIDDEN']['KRAS4D_CFGPATH']
    config_name = os.environ['KRAS4D_CFGNAME'] if \
        'KRAS4D_CFGNAME' in os.environ else service_config['HIDDEN']['KRAS4D_CFGNAME']
    config = Path(config_path).joinpath(config_name)
    # read from config file
    if config.is_file():
        with open(config, 'r') as cfg:
            try:
                body = yaml.safe_load(cfg)
                set_var('COMMON', body['common']) if 'common' in body else None
                set_var('CONTROL', body['control']) if 'control' in body else None
                if 'repositories' in body:
                    copy_registry(body['repositories'])
            except yaml.YAMLError as ex:
                print(f'bad yaml file {config_name}: {ex}, use default configuration before apply environments')
    else:
        print(f'unable to open file {config}, use default configuration before apply environments')
    # --privileged
    check_privileged_mode()
    # read environments
    set_env('COMMON')
    set_env('CONTROL')
