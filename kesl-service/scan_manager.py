import uuid
import time
import tasker
import logging
import requests
import threading
import service_util
import service_types
from string import Template
from datetime import datetime
from db_control import ScansStorage
from kesl_control import KESLControl
from configurator import service_config
from podman_control import PodmanControl
from docker_apiv2 import create_registry_context, update_registry_context


class CalcProgress:

    def __init__(self, total):
        self.total = total
        self.current = 0

    def calc(self, current):
        self.current = current
        return int((100 * current)/self.total)

    def plus(self, delta):
        self.current += delta
        return self.calc(self.current)


class ScanManager(ScansStorage):

    def __init__(self):
        self.scan_sessions_map = dict()
        self.database_path = None
        ScansStorage.__init__(self)
        self.log = logging.getLogger('main.scan_mgr')

    def final_construct(self, database_path):
        # init database
        self.database_path = database_path
        ScansStorage.final_construct(self, database_path)
        response, code = self.connect()
        if code != 0:
            self.log.error(f'unable to construct database object with error {response}')
        else:
            self.read_database()
        return response, code

    def add_scan_request(self, scan_session):
        guid = str(uuid.uuid4())
        scan_session.update({'scan_id': guid})
        self.scan_sessions_map[guid] = scan_session
        response, app_code = self.add_record(guid, scan_session)
        if app_code != 0:
            self.log.error(f'unable to add scan to database with error {response}')
        return guid

    def read_database(self):
        self.log.debug(f're-read scans database')
        rows, code = self.db_get_records()
        if code != 0:
            self.log.error(f'unable to read database with error {rows}')
            return None
        for row in rows:
            scan_session = service_types.upload_dict(service_types.scan_session_scheme, row)
            if not scan_session['scan_id'] in self.scan_sessions_map:
                self.scan_sessions_map[scan_session['scan_id']] = scan_session

    def show_all(self, force: bool):
        if force:
            self.read_database()
        scans_array = dict()
        for item in self.scan_sessions_map:
            scans_array[item] = {
                'status': self.scan_sessions_map[item]['scan_summary']['status'],
                'progress': self.scan_sessions_map[item]['scan_summary']['progress']
            }
        return scans_array

    def show_scan_id(self, guid, force: bool):
        if force:
            self.read_database()
        if guid in self.scan_sessions_map:
            return self.scan_sessions_map[guid]['scan_summary'], 0
            # return json.dumps(self.scan_sessions_map[guid]['scan_summary'],
            #                  indent=4, default=service_util.json_default_decode), 0
        else:
            return None, -1

    def sync_scan(self, guid):
        # return self.scan_method(guid, True)
        return self.scan_method(guid, True)

    def async_scan(self, guid):
        th = threading.Thread(target=self.scan_method, args=(guid,))
        th.start()

    def append_scan_error(self, guid, code, message, details=None):
        if code != 0:
            error_info = {'code': code, 'message': message}
            if details is not None:
                error_info.update({'details': details})
            self.scan_sessions_map[guid]['scan_summary']['scan_errors'].append(error_info)

    def scan_method(self, guid, sync=False):
        """
        todo: check for restart semaphore and add scan thread count
        """
        task_interceptor = tasker.Tasker()
        while task_interceptor.restart_semaphore_state:
            self.log.debug('restart semaphore detected: wait for restart...')
            time.sleep(1)
        task_interceptor.st_inc()
        verdict_list = []
        current_session_info = self.scan_sessions_map[guid]
        skip_exists_image = current_session_info['scan_summary']['scan_params']['skipimageifexists'] if \
            service_util.key_exists(current_session_info, 'scan_summary', 'scan_params', 'skipimageifexists') \
            else service_config['CONTROL']['KRAS4D_SKIPIMAGEIFEXISTS']
        destination_ctx, destination_host, destination_logged = None, None, None
        pm_control, av_control, name_postfix = PodmanControl(), KESLControl(), 0
        if current_session_info['session_info']['type'] == 'image':
            # source login & create context
            response, code = create_registry_context(current_session_info['session_info']['source'])
            if code != 0:
                self.append_scan_error(guid, code, f'unable to create registry context', response)
                return self.scan_sessions_map[guid]['scan_summary']
            response_login, code = pm_control.podman_login(response['context'])
            if code != 0:
                self.scan_sessions_map[guid]['scan_summary']['scan_errors'].append(response_login)
            response, code = update_registry_context(response, skip_exists_image)
            # TODO: return error
            self.append_scan_error(guid, code, 'Invalid source', response)
            self.scan_sessions_map[guid]['scan_summary']['scan_errors'].append(response['errors'])
            self.scan_sessions_map[guid]['session_info']['items'].update(response['images'])
            self.scan_sessions_map[guid]['session_info']['context'].update(response['context'])
            destination_host = current_session_info['scan_summary']['scan_params'][
                'destination'] if service_util.key_exists(current_session_info, 'scan_summary', 'scan_params',
                                                          'destination') else None
            if destination_host:
                destination_ctx, _ = create_registry_context(destination_host)
                response, code = pm_control.podman_login(destination_ctx['context'])
                destination_logged = True if code == 0 else False
                self.append_scan_error(guid, code,
                                       f'unable login to destination {destination_ctx["context"]["repository"]}',
                                       response)
                if skip_exists_image:
                    destination_ctx, code = update_registry_context(destination_ctx, True, True)
                    self.append_scan_error(guid, code, 'Unable to get images hash from destination registry')

            #  print(f'*** SOURCE:\n{json.dumps(self.scan_sessions_map[guid]["session_info"], indent=4)}')
            #  print(f'*** DESTINATION:\n{json.dumps(destination_ctx, indent=4)}')

        progress = CalcProgress(len(current_session_info['session_info']['items']))
        for item in current_session_info['session_info']['items']:
            iid = None
            name_postfix += 1
            self.scan_sessions_map[guid]['scan_summary']['progress'] = progress.plus(1)
            start_date = service_util.reformat_datetime_object(datetime.now())

            if current_session_info['session_info']['type'] == 'stream':
                scan_info = {item: current_session_info['session_info']['items'][item]}
                response, code = av_control.complete_scan(f'{guid}_{str(name_postfix)}', scan_info, 'ODS')
                service_util.soft_remove(scan_info[item])  # Path(scan_info[item]).un link(missing_ok=True)
            else:
                response, code = None, 0
                if skip_exists_image \
                        and item in destination_ctx['images'] \
                        and destination_ctx['images'][item] is not None \
                        and current_session_info['session_info']['items'][item] is not None \
                        and destination_ctx['images'][item] == current_session_info['session_info']['items'][item]:
                    response = {
                        'info': 'image exists and skipped',
                        'verdict': 'skipped'
                    }
                else:
                    if_tls = current_session_info['session_info']['context']['repository_schm'] == 'https'
                    iid, code = pm_control.podman_pull(current_session_info['session_info']['context']['repository'],
                                                       item, if_tls)
                    if code != 0:
                        self.append_scan_error(guid, code, f'podman: unable pull image {item}', iid)
                        continue
                    self.log.debug(f'start complete scan {item} iid:{iid}')
                    response, code = av_control.complete_scan(f'{guid}_{str(name_postfix)}', {item: iid},
                                                              'ContainerScan')
            stop_date = service_util.reformat_datetime_object(datetime.now())
            if code == 0:
                response['started'], response['stopped'] = start_date, stop_date
            append_data = {item: {'error': response}} if code != 0 else {item: response}
            verdict_list.append(response['verdict']) if 'verdict' in response else 'error'
            self.log.debug(f'item {item} verdicts: {verdict_list}')
            self.scan_sessions_map[guid]['scan_summary']['scan_result'].update(append_data)
            # TODO:
            # self.db_update_progress(guid, self.scan_sessions_map[guid])
            if current_session_info['session_info']['type'] == 'image':
                if destination_logged is not None and 'verdict' in response and response['verdict'] == 'clean':
                    stg = f'{current_session_info["session_info"]["context"]["repository"]}/{item}'.replace('//', '/')
                    dtg = f'{destination_ctx["context"]["repository"]}/' \
                          f'{destination_ctx["context"]["image_mask"]}/{item}'.replace('//', '/')
                    response, code = pm_control.podman_retug(stg, dtg)
                    if code != 0:
                        self.append_scan_error(guid, code, f'podman: unable re-tag image {stg}: {dtg}', response)
                    else:
                        if_tls = destination_ctx['context']['repository_schm'] == 'https'
                        response, code = pm_control.podman_push(dtg, if_tls)
                        self.append_scan_error(guid, code, f'podman: unable push image {dtg}', response)
                response, code = pm_control.podman_remove(iid)
                self.append_scan_error(guid, code, f'podman: unable to delete image {item}', response)
        # self.scan_sessions_map[guid]['scan_summary'] = remove_empty(self.scan_sessions_map[guid]['scan_summary'])
        self.scan_sessions_map[guid]['scan_summary']['verdicts'] = list(dict.fromkeys(verdict_list))
        self.finalize_scan(guid)
        """
        todo: decrease scan threads count 
        """
        task_interceptor.st_dec()
        if sync:
            return self.scan_sessions_map[guid]['scan_summary']

    def finalize_scan(self, guid):
        self.scan_sessions_map[guid]['scan_summary']['status'] = 'completed'
        self.scan_sessions_map[guid]['scan_summary']['completed'] = \
            service_util.reformat_datetime_object(datetime.now())
        self.db_full_update(guid, self.scan_sessions_map[guid])
        if service_util.key_exists(self.scan_sessions_map[guid], 'scan_summary', 'scan_params', 'custom_callbacks'):
            short = self.scan_sessions_map[guid]['scan_summary']['scan_result']
            subst = {
                '$infected': {item: short[item] for item in short if 'verdict'
                              in short[item] and short[item]['verdict'] == 'infected'},
                '$clean': {item: short[item] for item in short if 'verdict'
                           in short[item] and short[item]['verdict'] == 'clean'},
                '$skipped': {item: short[item] for item in short if 'verdict'
                             in short[item] and short[item]['verdict'] == 'skipped'}
            }
            for clbk in self.scan_sessions_map[guid]['scan_summary']['scan_params']['custom_callbacks']:
                response, code = self.send_clbk(
                    self.scan_sessions_map[guid]['scan_summary']['scan_params']['custom_callbacks'][clbk], subst)
                if code != 0:
                    self.scan_sessions_map[guid]['scan_summary']['scan_errors'].append({
                        'code': '-1',
                        'error': 'unable to send callback',
                        'details': response
                    })

    def json_replace(self, json_data, subst_data, result_data):
        for k in json_data:
            v = json_data[k]
            if isinstance(v, dict):
                result_data[k] = {}
                self.json_replace(v, subst_data, result_data)
            else:
                result_data[k] = subst_data[json_data[k]] \
                    if json_data[k].startswith('$') and json_data[k] in subst_data else v
        return result_data

    def send_clbk(self, clbk, subst):
        body = {}
        head = {'content-type': 'application/json'}
        if 'body' in clbk:
            if 'content-type' in clbk:
                if clbk['content-type'] == 'application/json':
                    result_data = self.json_replace(clbk['body'], subst, {})
                    body.update(result_data)
                elif clbk['content-type'] == 'text/plain':
                    result_data = (Template(clbk['body'])).substitute(subst)  # TODO: '$'
                    body.update(result_data)
                else:
                    body.update(clbk['body'])
        else:
            body = None
        try:
            response = requests.post(clbk['uri'], headers=head, json=body, timeout=2)
            if response.status_code != 200:
                self.log.warning(f'callback error: {response.status_code} {response.reason}')
            return '', 0
        except requests.exceptions.RequestException as ex:
            self.log.debug(f'callback error: {str(ex)}')
            return str(ex), -1
