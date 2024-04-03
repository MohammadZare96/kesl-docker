import time
import logging
import subprocess
import multiprocessing
from product_info import ProductInfo
from control import Control
from service_types import SpecSingleton


class Tasker(metaclass=SpecSingleton):

    app_status_info = {
        0  : 'success',
        64 : 'could not connect',
        74 : 'need restart',
        75 : 'need reboot',
        800: 'unknown status'
    }

    def __init__(self):
        self.log = logging.getLogger('main.tsk')
        # semaphore: restart
        self.restart_semaphore = False
        self.restart_semaphore_mutex = multiprocessing.Lock()
        # semaphore: scan thread count
        self.st_count = 0
        self.st_count_mutex = multiprocessing.Lock()
        # thread operations
        self.stop_thread = False
        self.stop_thread_mutex = multiprocessing.Lock()
        self.thread_point = multiprocessing.Process(target=self.thread_func)
        self.thread_point.start()

    def __del__(self):
        with self.stop_thread_mutex:
            self.stop_thread = True
        self.thread_point.join()

    """
    thread operations
    """
    @property
    def stop_thread_request(self):
        with self.stop_thread_mutex:
            return self.stop_thread

    def thread_func(self):
        command = 'kesl-control -W --q "EventType == \'TaskStateChanged\' ' \
                  'and TaskName == \'Update\' and TaskState == \'Stopped\'"'
        self.log.debug('task interceptor thread start')
        while not self.stop_thread_request:
            process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
            while not self.stop_thread_request:
                try:
                    data = process.stdout.readline().decode('utf-8').strip()
                    if data == '' and (process.poll() is not None):
                        break
                    if data != '':
                        if self.check_app_status() == 74:
                            self.log.debug(f'restart required')
                            self.do_restart()
                        break
                except KeyboardInterrupt:
                    print("EventReader process interrupted")
                    return
        self.log.debug(f'exit task interceptor thread')

    def check_app_status(self):
        control = Control('/usr/bin/kesl-control')
        info, code = control.run_command('--app-info')
        self.log.info(f'ROW app status {code}: {info}')
        return code

    def do_restart(self):
        product_info = ProductInfo()
        product_info.restart_flag = True
        self.set_restart_semaphore(True)
        while self.scan_thread_count != 0:
            time.sleep(1)
        # restart here
        control = Control('/etc/init.d/kesl')
        info, code = control.run_command('restart')
        self.log.info(f'kesl restarting with code {code}: {info}')
        self.set_restart_semaphore(False)
        product_info.restart_flag = False

    """
    restart semaphore
    """
    def set_restart_semaphore(self, state=True):
        with self.restart_semaphore_mutex:
            self.restart_semaphore = state

    @property
    def restart_semaphore_state(self):
        with self.restart_semaphore_mutex:
            return self.restart_semaphore

    """
        scan thread count
    """
    def st_inc(self):
        with self.st_count_mutex:
            self.st_count += 1

    def st_dec(self):
        with self.st_count_mutex:
            self.st_count -= (1 if self.st_count > 0 else 0)

    @property
    def scan_thread_count(self):
        with self.st_count_mutex:
            return self.st_count
