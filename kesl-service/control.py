import re
import os
import shlex
import logging
import pathlib
import subprocess
from configurator import service_config


class Control:

    def __init__(self, process_name, child_env=[]):
        self.permitted_env = ['http_proxy', 'https_proxy'] + child_env
        self.execution_env = {}
        self.control_log = logging.getLogger('main.control')
        self.process_name = process_name
        self.create_permitted_env()

    def create_permitted_env(self):
        for item in self.permitted_env:
            if item in os.environ:
                self.execution_env.update({
                    item: os.environ[item]
                })

    @staticmethod
    def secure_log(cmd: str):
        tmp_cmd = cmd
        if cmd.startswith('podman'):
            tmp_cmd = re.sub(pattern=r'(?<=-p )(.*?)(?= -)', repl='**********', string=cmd)
            tmp_cmd = re.sub(pattern=r'(?<=-u )(.*?)(?= -)', repl='**********', string=tmp_cmd)
        return tmp_cmd

    def run_command(self, args, timeout=None, ignore_code=False):
        if not pathlib.Path(self.process_name).is_absolute():
            self.control_log.warning(f'warning: relative execution disabled ({self.process_name})')
            return  f'warning: relative execution disabled ({self.process_name})', -1
        command = f'{self.process_name} {args}'
        timeout = int(timeout) if timeout else int(service_config['CONTROL']['KRAS4D_GENERALTIMEOUT'])
        self.control_log.debug(f'run command({self.secure_log(command)}, timeout={timeout})')
        try:
            process = subprocess.Popen(shlex.split(command), stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=False, env=self.execution_env)
            out_success, out_error = process.communicate(timeout=timeout)
            process.wait(timeout=timeout)
            return out_success.strip().decode('utf-8') if process.returncode == 0 or ignore_code \
                else out_error.strip().decode('utf-8'), process.returncode
        except subprocess.TimeoutExpired as e:
            return f'run_command timeout exception ({e.output})', -1
        except subprocess.CalledProcessError as e:
            return f'run_command called process exception ({e.output})', -1
        except (OSError, ValueError) as e:
            return f'run_command exception ({str(e)})', -1
