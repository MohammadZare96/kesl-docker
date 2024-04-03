import json
import uuid
import shutil
import logging
import validators
import service_util
import service_types
from pathlib import Path
from flask import request
from datetime import datetime
from service_util import remove_empty
from werkzeug.utils import secure_filename
from kesl_control import KESLControl
from scan_manager import ScanManager
from configurator import service_config
from make_error import CommonErrorResponse
from certificates_storage import CertificatesStorage


class Application(CommonErrorResponse):

    def __init__(self):
        self.log = logging.getLogger('main.app')
        self.podman_enabled = False
        self.self_activation = False
        self.scan_manager = ScanManager()
        self.cert_storage = CertificatesStorage(service_config['COMMON']['KRAS4D_CERTDIR'])
        #                                        service_config['HIDDEN']['KRAS4D_CRTDATA'])

    def final_construct(self):
        Path(service_config['COMMON']['KRAS4D_TMPPATH']).mkdir(parents=True, exist_ok=True)
        database_path = str(Path(service_config['COMMON']['KRAS4D_SQLPATH']).absolute())
        response, code = self.scan_manager.final_construct(database_path)
        if code != 0:
            self.log.error(f"unable to construct av manager: ({code}), response({response})")
        response, code = self.set_kesl_trace_level()
        if code != 0:
            self.log.error(f"unable to set kesl trace level: ({code}), response({response})")
        if service_config['CONTROL']['KRAS4D_ACTIVATION']:
            self.activate_engine(service_config['CONTROL']['KRAS4D_ACTIVATION'])
        if service_config['CONTROL']['KRAS4D_UPDATEOPTIONS']:
            response, code = self.setup_update_task()
            if code != 0:
                self.log.error(f'unable to setup Update task: {code} {response}')
        response, code = self.enable_podman()
        if code != 0:
            self.podman_enabled = False
            self.log.error(f"unable to enable podman mode: code({code}), response({response})")
        self.cert_storage.process_source()
        response, code = self.cert_storage.update_ca()
        if code != 0:
            self.log.error(f'Unable to update ca-bundle: {response}')
        if service_config['CONTROL']['KRAS4D_FORCEUPDATE']:
            print('update av bases. please, wait...')
            response, code = self.force_update()
            print(f"update complete with code: {code}")
            if code != 0:
                self.log.error(f'unable to download av databases:\n{response}')
        return True

    def done(self):
        self.log.debug('done application...')
        if self.self_activation is True:
            control = KESLControl()
            response, code = control.revoke()
            if code != 0:
                self.log.error(f'unable to revoke active key: {response}')

    @staticmethod
    def auth():
        if service_config['CONTROL']['KRAS4D_XAPIKEY']:
            auth_key = str(request.headers.get('x-api-key'))
            return (auth_key is not None) and (auth_key == service_config['CONTROL']['KRAS4D_XAPIKEY'])
        return True

    @staticmethod
    def force_update():
        control = KESLControl()
        return control.update_bases()

    @staticmethod
    def enable_podman():
        control = KESLControl()
        return control.enable_disable_podman(True)

    @staticmethod
    def setup_update_task():
        control = KESLControl()
        return control.setup_update_task(service_config['CONTROL']['KRAS4D_UPDATEOPTIONS'])

    @staticmethod
    def set_kesl_trace_level():
        if service_config['COMMON']['KRAS4D_LOGLEVEL'].strip().upper() != 'NOSET':
            control = KESLControl()
            return control.set_trace_level('Detailed')
        return '', 0

    def activate_engine(self, activation_code, attempts=5):
        # normalize (if key file)
        code_path = Path(service_config['COMMON']['KRAS4D_KEYPATH']).joinpath(activation_code).absolute()
        code_path = str(code_path) if code_path.is_file() else activation_code
        control, attempt = KESLControl(), 1
        while attempt != attempts:
            self.log.debug(f"try to activate KESL (attempt:{attempt})")
            response, app_code = control.activate(code_path)
            if app_code == 0:  # or app_code == 65:
                self.log.debug(f"activation success: <{response}>")
                self.self_activation = True
                break
            self.log.error(f"unable to activate KESL (code: {app_code}) with error: {response}")
            attempt += 1

    def unpack_body(self, content_type):
        result, error_code = [], None
        tmp_folder = Path(service_config['COMMON']['KRAS4D_TMPPATH'])
        self.log.debug(f'REQUEST: /ADDCERT POST from {request.remote_addr} content-type: ({content_type}')
        if content_type.startswith('application/octet-stream'):
            name = f'{str(uuid.uuid4())}.crt'
            path = str(tmp_folder.joinpath(name).absolute())
            try:
                with open(path, 'wb+') as (stream):
                    stream.write(request.get_data())
            except (OSError, ValueError, Exception) as ex:
                error_code = str(ex)
                self.log.error(f"unable to create file from octet-stream: {error_code}", exc_info=True)
            result.append({
                'path': path,
                'name': name,
                'code': error_code
            })
        elif content_type.startswith('multipart/form-data'):
            if request.files:
                stream_dict = request.files.to_dict(flat=False)
                for key in stream_dict:
                    for stream in stream_dict[key]:
                        error_code = None
                        path = str(tmp_folder.joinpath(str(uuid.uuid4())).absolute())
                        name = secure_filename(stream.filename) if stream.filename else 'noname'
                        try:
                            stream.save(path)
                        except (OSError, ValueError, Exception) as ex:
                            error_code = str(ex)
                            self.log.error(f"unable to create file from multipart: {error_code}", exc_info=True)
                        result.append({
                            'path': path,
                            'name': name,
                            'code': error_code
                        })
        return result

    def add_certificate(self, content_type):
        if not self.auth():
            self.log.error(f'REQUEST NOT AUTHORIZED')
            return self.make_error(self.ERR_FORBIDDEN)
        objects = self.unpack_body(content_type)
        self.log.debug(f'certificate(s):\n{json.dumps(objects, indent=4)}')
        for item in objects:
            if item['code'] is None:
                cert_path = Path(service_config['COMMON']['KRAS4D_CERTDIR']).joinpath(item['name'])
                try:
                    # ca_err = None
                    shutil.move(Path(item['path']), cert_path)
                    hash_name, ca_err = self.cert_storage.add_cert(cert_path)
                    if ca_err == 0:
                        hash_name, ca_err = self.cert_storage.update_ca()
                    item['code'] = 'success' if ca_err == 0 else hash_name
                except (OSError, ValueError, Exception) as ex:
                    item['code'] = str(ex)
        return json.dumps(objects, indent=4), 200

    def show_all(self):
        self.log.debug(f'REQUEST: /SCANS GET from {request.remote_addr} force:%s', ('force' in request.args))
        if not self.auth():
            self.log.error(f'REQUEST NOT AUTHORIZED')
            return self.make_error(self.ERR_FORBIDDEN)
        return self.scan_manager.show_all(('force' in request.args)), 200

    def show_scan_id(self, guid):
        if not self.auth():
            self.log.error(f'REQUEST NOT AUTHORIZED')
            return self.make_error(self.ERR_FORBIDDEN)
        self.log.debug(f'REQUEST: /SCANS/{guid} GET from {request.remote_addr} force:%s', ('force' in request.args))
        response, code = self.scan_manager.show_scan_id(guid, ('force' in request.args))
        return (remove_empty(response), 200) if code == 0 else self.make_error(self.ERR_OBJECT_NOT_FOUND)

    @staticmethod
    def validate_url(scan_session):
        bad_data = []
        if not validators.url(scan_session['session_info']['source']):
            bad_data.append({'source': scan_session['session_info']['source']})
        if service_util.key_exists(scan_session,
                                   'scan_summary', 'scan_params', 'destination') and \
                not validators.url(scan_session['scan_summary']['scan_params']['destination']):
            bad_data.append({'destination': scan_session['scan_summary']['scan_params']['destination']})
        if service_util.key_exists(scan_session,
                                   'scan_summary', 'scan_params', 'custom_callbacks', 'on_detect', 'uri') and \
                not validators.url(scan_session['scan_summary']['scan_params']['custom_callbacks']['on_detect']['uri']):
            bad_data.append({'on detect uri':
                            scan_session['scan_summary']['scan_params']['custom_callbacks']['on_detect']['uri']})
        if service_util.key_exists(scan_session,
                                   'scan_summary', 'scan_params', 'custom_callbacks', 'on_complete', 'uri') and \
                not validators.url(scan_session['scan_summary']['scan_params']['custom_callbacks']['on_complete']['uri']):
            bad_data.append({'on detect uri':
                            scan_session['scan_summary']['scan_params']['custom_callbacks']['on_complete']['uri']})
        return bad_data

    #
    # TODO: re-use unpack_body
    #
    def scan_request(self, content_type, sync_scan):
        if not self.auth():
            self.log.error(f'REQUEST NOT AUTHORIZED')
            return self.make_error(self.ERR_FORBIDDEN)
        scan_session = service_types.new_scan_session()
        scan_session['scan_summary'].update({
            'status' : 'created',
            'created': service_util.reformat_datetime_object(datetime.now())
        })
        self.log.debug(f"scan_request content-type({content_type} sync-scan({sync_scan})")
        if content_type.startswith('application/octet-stream'):
            scan_session['session_info'].update({
                'type'  : 'stream',
                'source': 'application/octet-stream'
            })
            path = str(Path(service_config['COMMON']['KRAS4D_TMPPATH']).joinpath(str(uuid.uuid4())).absolute())
            try:
                with open(path, 'wb+') as (stream):
                    stream.write(request.get_data())
                # scan_session['session_info']['items'].append({'noname': path})
                scan_session['session_info']['items'].update({'noname': path})
            except (OSError, ValueError, Exception) as ex:
                self.log.error(f"unable to create file from octet-stream: {str(ex)}", exc_info=True)
                return self.make_error(self.ERR_INTERNAL_SERVER_ERROR, str(ex))
        elif content_type.startswith('multipart/form-data'):
            scan_session['session_info'].update({
                'type'  : 'stream',
                'source': 'multipart/form-data'
            })
            if request.files:
                try:
                    stream_dict = request.files.to_dict(flat=False)
                    for key in stream_dict:
                        for stream in stream_dict[key]:
                            path = str(Path(service_config['COMMON']['KRAS4D_TMPPATH'])
                                       .joinpath(str(uuid.uuid4())).absolute())
                            stream.save(path)
                            scan_session['session_info']['items'].update({
                                secure_filename(stream.filename) if stream.filename else 'noname': path
                            })
                except (OSError, ValueError, Exception) as ex:
                    self.log.error(f"unable to create file from multipart/form-data: {str(ex)}", exc_info=True)
                    return self.make_error(self.ERR_INTERNAL_SERVER_ERROR, str(ex))
            if 'params' in request.form:
                try:
                    scan_session['scan_summary']['scan_params'] = json.loads(request.form['params'])
                except (OSError, ValueError, Exception) as ex:
                    self.log.error(f"invalid json: {str(ex)}", exc_info=True)
                    return self.make_error(self.ERR_INVALID_JSON, str(ex))
        elif content_type.startswith('application/json'):
            scan_session['session_info'].update({'type': 'image'})
            try:
                data = json.loads(request.data)
                scan_session['session_info'].update({'source': data['source'] if 'source' in data else None})
                scan_session['scan_summary'].update({'scan_params': data['params'] if 'params' in data else None})
                check_result = self.validate_url(scan_session)
                if len(check_result) != 0:
                    return self.make_error(self.ERR_INVALID_URL_FORMAT, check_result)
            except (OSError, ValueError, Exception) as ex:
                self.log.error(f"invalid json: {str(ex)}", exc_info=True)
                return self.make_error(self.ERR_INVALID_JSON, str(ex))
        elif content_type.startswith('text/plain'):
            scan_session['session_info'].update({
                'type'  : 'image',
                'source': request.data.strip().decode('utf-8')
            })
            check_result = self.validate_url(scan_session)
            if len(check_result) != 0:
                return self.make_error(self.ERR_INVALID_URL_FORMAT, check_result)
        if (scan_session['session_info']['type'] == 'stream' and bool(scan_session['session_info']['items']) is False) \
                or (scan_session['session_info']['type'] == 'image' and scan_session['session_info']['source'] is None):
            return self.make_error(self.ERR_NOTHING_TO_PROCESS)
        guid = self.scan_manager.add_scan_request(scan_session)
        try:
            if sync_scan:
                return remove_empty(self.scan_manager.sync_scan(guid)), 200
            self.scan_manager.async_scan(guid)
            return ({
                'id': guid,
                'location': '/scans/' + guid}), 201
        except (OSError, ValueError, Exception) as ex:
            self.log.error(f'scan exception {str(ex)}', exc_info=True)
            return self.make_error(self.ERR_INTERNAL_SERVER_ERROR, str(ex))
