import copy
import json
import pathlib
from dateutil import parser
from datetime import datetime
from service_types import SecureString


def json_default_decode(o):
    if isinstance(o, datetime):
        return o.isoformat()
    if isinstance(o, pathlib.WindowsPath) or isinstance(o, pathlib.PosixPath) or isinstance(o, SecureString):
        return str(o)


def json_secure(source: dict):
    def replace(what, tmp: dict):
        for key in tmp:
            if isinstance(tmp[key], dict):
                replace(what, tmp[key])
            if isinstance(tmp[key], list):
                for item in tmp[key]:
                    replace(what, item)
            if key in what:
                tmp[key] = '**********'
    tmp_source, tmp_what = copy.deepcopy(source), ['pass', 'password', 'pwd']
    replace(tmp_what, tmp_source)
    return tmp_source


def json_dumps2(o):
    if isinstance(o, dict):
        return json.dumps(o, indent=4, default=json_default_decode)
    return o


def key_exists(item, *keys):
    if not isinstance(item, dict):
        raise AttributeError('key_in_dict: not dict')
    _item = item
    for key in keys:
        try:
            _item = _item[key]
        except (KeyError, TypeError):
            return False
    return True


def remove_empty(item):
    if not isinstance(item, (dict, list)):
        return item
    if isinstance(item, list):
        return [v for v in (remove_empty(v) for v in item) if v]
    return {k: v for k, v in ((k, remove_empty(v)) for k, v in item.items()) if v}


def reformat_datetime_string(date_string):
    try:
        return parser.parse(date_string).astimezone().isoformat()
    except Exception as ex:
        return f'datetime error {ex}'


def reformat_datetime_object(date_object: datetime):
    return date_object.astimezone().isoformat()


def soft_remove(path: str):
    # noinspection PyBroadException
    try:
        pathlib.Path(path).unlink()
    except Exception:
        pass
