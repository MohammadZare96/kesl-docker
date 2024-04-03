import shlex
import logging
import subprocess
import service_util
from control import Control
from configurator import service_config


class KESLControl(Control):

    COMMAND_ACTIVATE              = '--add-active-key {}'
    COMMAND_ENABLE_DISABLE_PODMAN = '--set-cont UsePodman={} PodmanRootFolder={}'
    COMMAND_CREATE_TASK           = '--create-task {} --type {}'
    COMMAND_SET_SET               = '--set-set {} '
    COMMAND_START_TASK            = '--start-task {} -W'
    COMMAND_START_TASK_RUNTIME    = '/usr/bin/kesl-control --start-task {} -W'
    COMMAND_DELETE_TASK           = '--delete-task {}'
    COMMAND_REVOKE                = '--remove-active-key'
    COMMAND_SET_TRACE_LEVEL       = '--set-app-settings TraceLevel={}'
    COMMAND_SETUP_UPDATE_TASK     = '--set-set Update {}'

    def __init__(self):
        self.log = logging.getLogger('main.kesl-control')
        Control.__init__(self, '/usr/bin/kesl-control')

    def activate(self, activation_code):
        command = self.COMMAND_ACTIVATE.format(activation_code)
        return self.run_command(command)

    def revoke(self):
        command = self.COMMAND_REVOKE
        return self.run_command(command)

    def set_trace_level(self, level_name):
        command = self.COMMAND_SET_TRACE_LEVEL.format(level_name)
        return self.run_command(command)

    def setup_update_task(self, options):
        command = self.COMMAND_SETUP_UPDATE_TASK.format(options)
        return self.run_command(command)

    def enable_disable_podman(self, enable=True):
        enabled = 'Yes' if enable else 'No'
        command = self.COMMAND_ENABLE_DISABLE_PODMAN.format(enabled, '/var/lib/containers/vfs-storage/')
        return self.run_command(command)

    def create_task(self, name, scan_type):
        command = self.COMMAND_CREATE_TASK.format(name, scan_type)
        return self.run_command(command)

    def task_settings(self, name, options):
        command = self.COMMAND_SET_SET.format(name)
        for key in options:
            command += f'{key}={options[key]} '
        return self.run_command(command)

    def update_bases(self):
        command = self.COMMAND_START_TASK.format('Update')
        return self.run_command(command, service_config['CONTROL']['KRAS4D_UPDTASKTIMEOUT'])

    def delete_task(self, name):
        command = self.COMMAND_DELETE_TASK.format(name)
        return self.run_command(command)

    def collect_scan_task_events(self, name):
        event, response = {}, []
        command = self.COMMAND_START_TASK_RUNTIME.format(name)
        self.log.debug(f'start task: <{command}>')
        process = subprocess.Popen(shlex.split(command), stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=False, env={})
        while True:
            out_success = process.stdout.readline().decode('utf-8').strip()
            if out_success == '' and (process.poll() is not None):
                if bool(event):
                    response.append(dict(event))
                    # TODO callback(event)
                break
            if out_success != '':
                if out_success.startswith('EventType'):
                    if bool(event):
                        response.append(dict(event))
                        # TODO callback(event)
                        event = {}
                    event['EventType'] = out_success.split('=')[1]
                else:
                    if bool(event):
                        if '=' in out_success:
                            k, v = out_success.split('=', 1)
                            event[k] = v
        if process.returncode != 0:
            out_error = process.stderr.readline().decode('utf-8').strip()
            return out_error, process.returncode
        return response, 0

    def complete_scan(self, guid: str, scan_item, scan_type):
        item_name = next(iter(scan_item))
        task_name = f"kras4d_{guid.replace('-', '_')}"
        # create task
        response, code = self.create_task(task_name, scan_type)
        if code != 0:
            self.log.error(f'unable to create {scan_type} task {task_name} with error: {response}')
            return f'unable to create {scan_type} task {task_name} with error: {response}', -1
        # settings
        settings = {
            'FirstAction': 'Skip',
            'SecondAction': 'Skip'
        }
        settings.update({'ScanScope.item_0000.Path': scan_item[item_name]} if scan_type == 'ODS'
                        else {'ImageNameMask': scan_item[item_name]})
        # settings = {'ScanScope.item_0000.Path': scan_item[item_name]} \
        #    if scan_type == 'ODS' else {'ImageNameMask': scan_item[item_name]}
        response, code = self.task_settings(task_name, settings)
        if code != 0:
            # TODO delete task
            self.log.error(f'unable to apply settings to {scan_type} task {task_name} with error: {response}')
            return f'unable to apply settings to {scan_type} task {task_name} with error: {response}', -1
        # start scan
        scan_result = dict()
        scan_result['error'] = []
        events, code = self.collect_scan_task_events(task_name)
        if code == 0:
            tmp_threats, tmp_errors = [], []
            scan_result['verdict'] = 'clean'
            for event in events:
                self.log.debug(f'event:\n{service_util.json_dumps2(event)}')
                if event['EventType'] == 'TaskStateChanged':
                    if event['TaskState'] == 'Started':
                        scan_result['started'] = service_util.reformat_datetime_string(event['Date'])
                    elif event['TaskState'] == 'Stopped':
                        scan_result['stopped'] = service_util.reformat_datetime_string(event['Date'])
                elif event['EventType'] == 'ThreatDetected':
                    tmp_threats.append({
                        'name': event['DetectName'],
                        'object': event['FileName']
                    })
                elif event['EventType'] == 'ObjectProcessingError':
                    tmp_errors.append({
                        'error': event['ObjectProcessError'] if 'ObjectProcessError' in event else 'generic',
                        'object': event['FileName']
                    })
            if tmp_threats:
                scan_result['threats'] = tmp_threats
                scan_result['verdict'] = 'infected'
            elif tmp_errors:
                scan_result['errors'] = tmp_errors
                scan_result['verdict'] = 'non scanned'
        else:
            scan_result['error'].append({
                'error': events
            })
        # delete task
        response, code = self.delete_task(task_name)
        if code != 0:
            self.log.warning(f'unable to delete task {task_name}: {response}')
        return scan_result, code
