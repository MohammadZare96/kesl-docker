import os
import logging
import subprocess
import control
from shutil import copyfile
from pathlib import Path as pt
from service_types import SpecSingleton


class CertificatesStorage(metaclass=SpecSingleton):
    def __init__(self, source, destination='/etc/pki/ca-trust/source/anchors/'):
        self.names = dict()
        self.source = pt(source).resolve()
        self.destination = pt(destination).resolve()
        self.log = logging.getLogger('main.cert')
        if not self.destination.is_dir():
            pt.mkdir(pt(destination), parents=True, exist_ok=True)

    def add_cert(self, source):
        hash_name, err = self.process_cert(source)
        self.log.info(f'new link: {source} ===> {hash_name}')
        if err == 0:
            # os.symlink(source, hash_name)
            copyfile(source, hash_name)
        return hash_name, err

    def process_source(self):
        if self.source.is_dir() and self.destination.is_dir():
            for item in self.source.iterdir():
                hash_name, err = self.add_cert(item)
                if err != 0:
                    self.log.error(f'Unable to process certificate file {item}: {hash_name}')

    def update_ca(self):
        command = control.Control('/usr/bin/update-ca-trust')
        response, code = command.run_command('')
        self.log.debug(f'update-ca-trust: {code}: {response}')
        return response, code

    def process_cert(self, name):
        hash_name, err = self.process_name(name)
        if err == 0:
            self.names[hash_name] = 0 if hash_name not in self.names else self.names[hash_name] + 1
            return self.destination.joinpath(hash_name + f'.{self.names[hash_name]}'), 0
        return hash_name, -1

    @staticmethod
    def process_name(name):
        command = control.Control('/usr/bin/openssl')
        return command.run_command(f'x509 -hash -noout -in {name}')
        """
        try:
            command = f'openssl x509 -hash -noout -in {name}'
            process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
            out_success, out_error = process.communicate(timeout=5)
            process.wait(timeout=5)
            return out_success.strip().decode('utf-8') if process.returncode == 0 \
                else out_error.strip().decode('utf-8'), process.returncode
        except Exception as ex:
            return f'run openssl exception ({ex})', -1
        """
