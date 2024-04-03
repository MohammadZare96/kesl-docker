import shlex
import base64
import urllib3
import fnmatch
import logging
import requests
import service_util
from urllib.parse import urlparse
from configurator import service_config


def request_apiv2_route_token(www_authenticate, headers, cert):
    method, route_part = www_authenticate.split(' ', 2)
    route_dict = dict([item.split('=') for item in route_part.split(',')])
    authenticate_route = \
        (route_dict['realm'].strip('"') if 'realm' in route_dict else '') + \
        (('?service=' + route_dict['service'].strip('"')) if 'service' in route_dict else '') + \
        (('?scope=' + route_dict['scope'].strip('"')) if 'scope' in route_dict else '')
    response = requests.get(authenticate_route, headers=headers, verify=cert)
    if response.status_code == 200:
        response_body = response.json()
        return method + ' ' + (response_body.get('access-token') or response_body['token']), 200
    return response.reason, response.status_code


def request_apiv2_route(route, token=None, user_name=None, user_pass=None, cert=None):
    headers = {'User-Agent': 'Docker-Client (linux)'}
    headers.update({'Content-Type': 'application/json'})
    try:
        if token is None:
            if user_name is not None and user_pass is not None:
                headers.update({
                    'Authorization':
                        'Basic ' + base64.b64encode((user_name + ':' + user_pass).encode('utf-8')).decode('utf-8')
                })
            response = requests.get(route, headers=headers, verify=cert)
            if response.status_code == 401 and 'Www-Authenticate' in response.headers:
                token, code = request_apiv2_route_token(
                    response.headers['Www-Authenticate'], headers=headers, cert=cert)
                return request_apiv2_route(route, token=token, cert=cert) if code == 200 else (token, code)
            return response.json() if response.status_code == 200 else response.reason, \
                response.headers if response.status_code == 200 else None, response.status_code
        else:
            headers.update({
                'Authorization': '{}'.format(token)
            })
            response = requests.get(route, headers=headers, verify=cert)
            return response.json() if response.status_code == 200 else response.reason, \
                response.headers if response.status_code == 200 else None, response.status_code
    except requests.exceptions.RequestException as e:
        return str(e), None, 500


def request_images(request_data, user_name=None, user_pass=None, cert=None):
    apiv2_route = '{}://{}/v2/_catalog'.format(request_data['context']['repository_schm'],
                                               request_data['context']['repository'])
    return request_apiv2_route(apiv2_route, user_name=user_name, user_pass=user_pass, cert=cert)


def request_tags(request_data, image_name, user_name=None, user_pass=None, cert=None):
    apiv2_route = '{}://{}/v2/{}/tags/list'.format(request_data['context']['repository_schm'],
                                                   request_data['context']['repository'], image_name)
    return request_apiv2_route(apiv2_route, user_name=user_name, user_pass=user_pass, cert=cert)


def request_digest(request_data, image, user_name=None, user_pass=None, cert=None):
    image_data = image.rsplit(':')
    apiv2_route = '{}://{}/v2/{}/manifests/{}' \
        .format(request_data['context']['repository_schm'], request_data['context']['repository'],
                image_data[0], image_data[1])
    response, headers, code = request_apiv2_route(apiv2_route, user_name=user_name, user_pass=user_pass, cert=cert)
    return (None
            if code != 200 else (None if 'Docker-Content-Digest' not in headers
                                 else headers['Docker-Content-Digest'])), 200


def create_registry_context(request_string):
    request_parts = urlparse(request_string)
    if request_parts.hostname is None:
        return 'Bad registry hostname', -1
    response = {
        'context': {
            'repository': request_parts.hostname + (f':{request_parts.port}' if request_parts.port else ''),
            'repository_schm': request_parts.scheme,
            'repository_port': request_parts.port,
            'repository_base': request_parts.hostname,
            'credentials': {
                'user': shlex.quote(request_parts.username),
                'pass': shlex.quote(request_parts.password)},
            'image_mask': (
                request_parts.path + '?' + request_parts.query) if request_parts.query else request_parts.path
        },
        'images': {},
        'errors': []
    }
    if not request_parts.username or not request_parts.password:
        tmp = f"{response['context']['repository_schm']}://{response['context']['repository']}"
        if service_config['REPOSITORIES'] and tmp in service_config['REPOSITORIES']:
            repository_data = service_config['REPOSITORIES'][tmp]
            response['context']['credentials']['user'] = repository_data['credentials'][
                'user'].value if service_util.key_exists(repository_data, 'credentials', 'user') else None
            response['context']['credentials']['pass'] = repository_data['credentials'][
                'pass'].value if service_util.key_exists(repository_data, 'credentials', 'pass') else None
        else:
            response['context']['credentials']['user'], response['context']['credentials']['pass'] = None, None
    return response, 0


def update_registry_context(context, request_sha256=False, expand_mask=False):
    separator = ['?', '*']
    urllib3.disable_warnings()
    logging.debug(f'update_registry_context expand={expand_mask}')
    # for future use
    # repository_name = context['context']['repository']
    # repository_data = service_config['REPOSITORIES'][repository_name] if service_util.key_exists(
    #    service_config, 'REPOSITORIES', repository_name) else None
    # verify = str(Path(service_config['COMMON']['KRAS4D_CERTDIR']).joinpath(
    #    repository_data['certificate'])) if repository_data and 'certificate' in repository_data else None
    # verify = service_config['HIDDEN']['KRAS4D_CRTDATA']
    verify = True if context['context']['repository_schm'] == 'https' else False
    tmp = (context['context']['image_mask'] + '/*:*')[1:] if expand_mask else context['context']['image_mask'][1:]
    tags_mask = tmp.rsplit(':', 1)[1] if ':' in tmp else '*'
    name_mask = tmp.rsplit(':', 1)[0] if ':' in tmp else tmp
    name_list = [name_mask]
    user_name = context['context']['credentials']['user']
    user_pass = context['context']['credentials']['pass']
    if any(item in name_mask for item in separator):
        name_list.clear()
        tmp, _, code = request_images(context, user_name=user_name, user_pass=user_pass, cert=verify)
        if code != 200:
            context['errors'].append(tmp)
            return context, code
        name_list = fnmatch.filter(tmp['repositories'], name_mask)
    if expand_mask:
        tmp_names = []
        for item in name_list:
            tmp_names.append(item[len(context['context']['image_mask']):])
        name_list = tmp_names
    if any(item in tags_mask for item in separator):
        for item in name_list:
            tag_list, _, code = request_tags(context, item, user_name=user_name, user_pass=user_pass, cert=verify)
            if code != 200:
                context['errors'].append({item: tag_list})
            else:
                tag_list = fnmatch.filter(tag_list['tags'], tags_mask)
                for tag in tag_list:
                    context['images'].update({
                        '{}:{}'.format(item, tag): ''
                    })
    else:
        for item in name_list:
            context['images'].update({
                '{}:{}'.format(item, tags_mask): ''
            })
    if request_sha256:
        for item in context['images']:
            sha256, app_code = request_digest(context, item, user_name=user_name, user_pass=user_pass, cert=verify)
            context['images'].update({item: sha256})
    return context, 0
