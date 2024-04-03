import json


class SpecSingleton(type):

    _instances = {}

    def __call__(cls, *args, **kwargs):
        if cls not in cls._instances:
            cls._instances[cls] = super(SpecSingleton, cls).__call__(*args, **kwargs)
        return cls._instances[cls]


support_contents = (
    'text/plain', 'application/json', 'application/octet-stream', 'multipart/form-data'
)

support_cert_contents = (
    'application/octet-stream', 'multipart/form-data'
)


def new_scan_session():
    scan_session = {
        'scan_id': None,
        'scan_summary': {
            'status'      : None,
            'created'     : None,
            'completed'   : None,
            'progress'    : 0,
            'scan_params' : None,
            'scan_errors' : [],
            'scan_result' : {}
        },
        'session_info': {
            'type'   : None,
            'source' : None,
            'context': {},
            'items'  : {}
        }
    }
    return scan_session


scan_session_scheme = dict([
    ('scan_id', lambda s, _: s[0]),
    ('scan_summary', dict([
        ('status'   , lambda s, _: s[1]),
        ('created'  , lambda s, _: s[2]),
        ('completed', lambda s, _: s[3]),
        ('progress' , lambda s, _: s[4]),
        ('scan_params', lambda s, _: json.loads(s[5])),
        ('scan_errors', lambda s, _: json.loads(s[6])),
        ('scan_result', lambda s, _: json.loads(s[7]))
    ])),
    ('session_info', lambda s, _: json.loads(s[8]))
])


def upload_dict(spec, array):
    result = dict()
    for key, getter in spec.items():
        if callable(getter):
            result[key] = getter(array, False)
        else:
            assert isinstance(getter, dict)
            result[key] = upload_dict(getter, array)
    return result


class SecureString:

    def __init__(self, value=None):
        self.__value = value

    def __str__(self):
        return '**********'

    def __repr__(self):
        return '**********'

    @property
    def value(self):
        return self.__value

    @value.setter
    def value(self, value):
        self.__value = value
