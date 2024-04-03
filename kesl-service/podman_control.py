import logging
from configurator import service_config
from control import Control


class PodmanControl(Control):

    COMMAND_LOGIN  = 'login {} -u {} -p {} --cert-dir {} '
    COMMAND_PULL   = 'pull --cert-dir {} --tls-verify={} {}/{}'
    COMMAND_RETAG  = 'tag {} {}'
    COMMAND_PUSH   = 'push --cert-dir {} --tls-verify={} {}'
    COMMAND_REMOVE = 'rmi {} --force'

    def __init__(self):
        self.log = logging.getLogger('main.podman')
        init_arg = '/usr/bin/podman' if service_config['HIDDEN']['KRAS4D_PRVMODE'] is True \
            else '/usr/bin/podman --storage-driver vfs --root /var/lib/containers/vfs-storage/'
        Control.__init__(self, init_arg)

    def podman_login(self, repository_data):
        host = service_config['REPOSITORIES'][repository_data['repository']] if \
            service_config['REPOSITORIES'] and repository_data['repository'] in service_config['REPOSITORIES'] else None
        user = repository_data['credentials']['user'] if repository_data['credentials']['user'] \
            else host['credentials']['user'] if host and 'credentials' in host else None
        password = repository_data['credentials']['pass'] if repository_data['credentials']['pass'] \
            else host['credentials']['pass'] if host and 'credentials' in host else None
        if user and password:
            command = self.COMMAND_LOGIN.format(
                repository_data['repository'], user, password, service_config['COMMON']['KRAS4D_CERTDIR'])
            self.log.debug(f'try login to: {repository_data["repository"]}')
            return self.run_command(command)
        # TODO: Public login?
        else:
            return 'no creds', 0

    def podman_pull(self, host, image, tls=True):
        command = self.COMMAND_PULL.format(service_config['COMMON']['KRAS4D_CERTDIR'],
                                           'true' if tls is True else 'false', host, image)
        return self.run_command(command)

    def podman_retug(self, source, destination):
        command = self.COMMAND_RETAG.format(source, destination)
        return self.run_command(command)

    def podman_push(self, image: str, tls=True):
        command = self.COMMAND_PUSH.format(service_config['COMMON']['KRAS4D_CERTDIR'],
                                           'true' if tls is True else 'false', image)
        return self.run_command(command)

    def podman_remove(self, image_id):
        command = self.COMMAND_REMOVE.format(image_id)
        return self.run_command(command)
