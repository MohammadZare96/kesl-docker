import os
import json
import signal
import tasker
import control
import service_types
from product_info import ProductInfo
from logger import init_logger
from application import Application
from distutils.dir_util import copy_tree
from service_util import json_default_decode, json_secure
from flask import Flask, request, make_response
from configurator import get_config, service_config
from subprocess import check_output

"""
    branch: docker_service_15
"""

main_app = Application
hook_app = Flask('kesl-service')
hook_app.config['APPLICATION_ROOT'] = '/v1/antivirus'


def create_response(message, user_code):
    user_response = make_response(message, user_code)
    user_response.headers['Content-Type'] = 'application/json'
    return user_response


@hook_app.route('/shutdown', methods=['GET'])
def main_shutdown():
    if main_app.auth() is True:
        exit_service()
        return create_response('{done}', 200)
    return create_response(*main_app.make_error(main_app.ERR_FORBIDDEN))


@hook_app.route('/status', methods=['GET'])
def show_status():
    if main_app.auth() is True:
        product_info = ProductInfo()
        return create_response(product_info.create_product_info(), 200)
    return create_response(*main_app.make_error(main_app.ERR_FORBIDDEN))


@hook_app.route('/scans', methods=['POST'])
def scan_request():
    if not request.content_type or not request.content_type.startswith(service_types.support_contents):
        main_app.log.warning(f'unsupported content type {request.content_type}')
        return create_response(
            *main_app.make_error(main_app.ERR_NOT_SUPPORTED_CONTENT_TYPE, details=request.content_type))
    product_info = ProductInfo()
    success, status = product_info.calculate_product_status()
    if not success:
        main_app.log.warning(f'service not ready: {status}')
        return create_response(
            *main_app.make_error(main_app.ERR_SERVICE_NOT_AVAILABLE, details=status))
    sync_scan = True if 'wait' in request.args and request.args.get('wait') == '1' else False
    user_response, user_code = main_app.scan_request(request.content_type, sync_scan)
    return create_response(user_response, user_code)


@hook_app.route('/scans', methods=['GET'])
def show_all():
    user_response, user_code = main_app.show_all()
    return create_response(user_response, user_code)


@hook_app.route('/scans/<string:guid>', methods=['GET'])
def show_scan_id(guid):
    user_response, user_code = main_app.show_scan_id(guid)
    return create_response(user_response, user_code)


@hook_app.route('/addcert', methods=['POST'])
def add_certificate():
    if not request.content_type or not request.content_type.startswith(service_types.support_cert_contents):
        main_app.log.warning(f'unsupported content type {request.content_type}')
        return create_response(
            *main_app.make_error(main_app.ERR_NOT_SUPPORTED_CONTENT_TYPE, details=request.content_type))
    user_response, user_code = main_app.add_certificate(request.content_type)
    return create_response(user_response, user_code)


def exit_service(signum=None, frame=None):
    print(f"Terminate signal({signum}) detected. Exit service")
    main_app.done()
    nagent_pid = map(int, check_output(["/bin/pidof", "klnagent"]).split())
    print("Terminate nagent")
    for pid in nagent_pid:
        print(f"\tpid: {pid}")
        os.kill(pid, signal.SIGTERM)
    os.kill(os.getgid(), signal.SIGINT)

if __name__ == '__main__':
    get_config()
    rotation = None
    if 'KRAS4D_LOGROTATE' in service_config['COMMON'] and service_config['COMMON']['KRAS4D_LOGROTATE'] is not None:
        if 'x' in servive_config['COMMON']['KRAS4D_LOGROTATE']:
            arr = service_config['COMMON']['KRAS4D_LOGROTATE'].split('x',2)
            rotation = (int(arr[0]), int(arr[1]))
    print(f'startup log rotation: {rotation}')
    main_log = init_logger(rotation=rotation)
    main_log.info('========== New Session ===========================================================================')
    main_log.debug(f'configuration:\n{json.dumps(json_secure(service_config), indent=4, default=json_default_decode)}')
    os.environ['REQUESTS_CA_BUNDLE'] = '/etc/ssl/certs/ca-bundle.trust.crt'
    try:
        # start kesl
        startup = control.Control('/root/kesl-service/startup.sh')
        response, code = startup.run_command('')
        print(f'startup script code: {code}')
        print(f'startup script info:\n{response}')
        # start tasker
        task_interceptor = tasker.Tasker()
        # init application
        signal.signal(signal.SIGTERM, exit_service)
        main_app = Application()
        final_result = main_app.final_construct()
        if final_result != True:
            exit_service()
        # start
        from waitress import serve
        serve(hook_app, listen='*:{}'.format(service_config['COMMON']['KRAS4D_PORT']))
    except (OSError, ValueError) as ex:
        main_log.error(f'application exception {str(ex)}', exc_info=True)
