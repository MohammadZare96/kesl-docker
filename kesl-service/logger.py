import time
import logging
from pathlib import Path
from configurator import service_config
from logging.handlers import RotatingFileHandler


def init_logger(rotation=(1024*1024, 10)):
    convert_lvl = {
        'DEBUG': logging.DEBUG, 'INFO': logging.INFO,
        'WARNING': logging.WARNING, 'ERROR': logging.ERROR, 'CRITICAL': logging.CRITICAL
    }
    try:
        Path(service_config['COMMON']['KRAS4D_LOGPATH']).mkdir(parents=True, exist_ok=True)
        # init logger
        main = logging.getLogger('main')
        main.setLevel(convert_lvl.get(service_config['COMMON']['KRAS4D_LOGLEVEL'].strip().upper(), logging.NOTSET))
        name = Path(service_config['COMMON']['KRAS4D_LOGPATH']).joinpath('kesl-service.log')
        file = RotatingFileHandler(name, maxBytes=rotation[0], backupCount=rotation[1]) \
            if rotation else logging.FileHandler(name)
        file.setFormatter(logging.Formatter('%(asctime)s %(name)15s [%(process)10d] [%(threadName)10s] '
                                            '%(levelname)8s %(message)s', '%Y-%m-%dT%H:%M:%S%z'))
        logging.Formatter.converter = time.gmtime
        main.addHandler(file)
        return main
    except (OSError, ValueError) as ex:
        main = logging.getLogger()
        main.error(f'unable to configure logging subsystem: {ex}')
        return main
