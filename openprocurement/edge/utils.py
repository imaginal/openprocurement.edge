# -*- coding: utf-8 -*-
from functools import partial
from couchdb.http import ResourceConflict
from cornice.resource import resource, view
from pkg_resources import get_distribution
from schematics.exceptions import ModelValidationError
from logging import getLogger
from requests import Session
from requests.auth import HTTPBasicAuth

from openprocurement.api import utils
from openprocurement.edge.traversal import tender_factory
from openprocurement.edge.models import Token, Task, ApiRequest, ApiResponse, get_now


# monkey patch api.utils for use views as normal functions

def null_decorator(**kw):
    def wrapper(klass):
        return klass
    return wrapper

utils.opresource = null_decorator
# utils.json_view = null_decorator

PKG = get_distribution(__package__)
LOGGER = getLogger(PKG.project_name)
SERVICE_FIELDS = ('__parent__', 'doc_type')
SESSION = Session()

json_view = partial(view, renderer='json')
APIResource = utils.APIResource

opresource = partial(resource, error_handler=utils.error_handler, factory=tender_factory)
# eaopresource = partial(resource, error_handler=error_handler, factory=auction_factory)
# contractingresource = partial(resource, error_handler=error_handler, factory=contract_factory)
# planningresource = partial(resource, error_handler=error_handler, factory=plan_factory)


def context_unpack(request, msg, params=None):
    return utils.context_unpack(request, msg, params)


def save_resource_item(db, item):
    if '_id' not in item:
        item['_id'] = item['id']
    try:
        item_doc = db.get(item['_id'])
        item['_rev'] = item_doc['_rev']
    except Exception:
        pass
    try:
        db.save(item)
    except Exception as e:
        message = '{}: {}'.format(type(e).__name__, e)
        LOGGER.error('Error save {} {}: {}'.format(item['doc_type'], item['_id'], message))
        return
    LOGGER.info('Update {} {} {}'.format(item['doc_type'], item['_id'], item['dateModified']))
    return True


def update_task_resource(request):
    task = request.validated['task']
    if not task.request.path:
        return
    parts = task.request.path.split('/', 3)
    if len(parts) < 3:
        return
    url = request.registry.remote_url + '/'.join(parts[:3])
    timeout = request.registry.remote_timeout
    try:
        res = SESSION.get(url, timeout=timeout)
        res.raise_for_status()
        item = res.json().get('data')
        if not item:
            raise ValueError('Bad response {}'.format(res.text))
    except Exception as e:
        message = '{}: {}'.format(type(e).__name__, e)
        LOGGER.error('Error update {} failed {}'.format(url, message))
        return
    if 'doc_type' not in item:
        item['doc_type'] = 'Tender'  # FIXME
    return save_resource_item(request.registry.db, item)


def save_token(request, token):
    try:
        token.validate()
        token.store(request.registry.db, validate=False)
    except ModelValidationError as e:
        for i in e.message:
            request.errors.add('body', i, e.message[i])
        return
    except ResourceConflict as e:  # pragma: no cover
        request.errors.add('body', 'data', str(e))
        return
    except Exception as e:  # pragma: no cover
        request.errors.add('body', 'data', str(e))
        return
    LOGGER.info('Saved token {} user {} path {}'.format(token.id, token.user, token.path),
                extra=context_unpack(request, {'MESSAGE_ID': 'save_token'}, {'RESULT': token.rev}))
    return True


def save_access_token(request, res, user=None):
    try:
        access = res.json().get('access')
    except (KeyError, ValueError):
        return
    if not access or not access.get('token'):
        return
    path = res.headers.get('Location', '/')
    token_id = path.rsplit('/', 1)[1]       # maybe not safe
    pos = path.find('/api/')
    if pos > 0:
        pos = path.find('/', pos + 5)
        path = path[pos:]
    if not token_id:
        token_id = utils.generate_id()
    if not user:
        user = request.validated['user_token']
    token = Token(dict(
        id=token_id,
        date=get_now(),
        user=user,
        path=path,
        token=access.get('token'),
        transfer=access.get('transfer')
    ))
    return save_token(request, token)


def run_task(request, acquired=False):
    task = request.validated['task']
    if not acquired:
        task.dateLastRun = get_now()
        if not save_task(request):
            return

    url = request.registry.remote_url + task.request.path
    headers = {'Content-Type': 'application/json'}
    if task.request.content_type:
        headers['Content-Type'] = task.request.content_type
    if task.request.acc_token:
        headers['X-Access-Token'] = task.request.acc_token
    if not SESSION.auth:
        SESSION.auth = HTTPBasicAuth(request.registry.remote_key, '')
    timeout = request.registry.remote_timeout

    try:
        method = task.request.method
        data = task.request.body
        res = SESSION.request(method, url, data=data, headers=headers, timeout=timeout)
        if res.status_code == 412 and 'Set-Cookie' in res.headers:
            LOGGER.info('New cookie {}'.format(res.headers['Set-Cookie']))
            res = SESSION.request(method, url, data=data, headers=headers, timeout=timeout)

        request.response.headers['X-Api-Request-ID'] = res.headers.get('X-Request-ID')
        task_res = ApiResponse().from_response(res)

        if res.status_code < 400:
            task.status = 'success'
            task.response = task_res
            save_access_token(request, res, user=task.user)
        else:
            task.append_error(task_res)
    except Exception as e:
        message = "{}: {}".format(type(e).__name__, e)
        task.append_error(dict(body=message))
        LOGGER.error('Error run task {} failed {}'.format(task.id, message))

    if task.status == 'error' and len(task.errors) >= request.registry.remote_retry:
        task.status = 'failed'

    utils.update_logging_context(request, {'TASK_STATUS': task.status})
    LOGGER.info('Run task {} {} -> {}'.format(task.id, task.request, task.status),
                extra=context_unpack(request, {'MESSAGE_ID': 'run_task'}, {'RESULT': task.status}))

    if not save_task(request):
        return

    if task.status == 'success':
        update_task_resource(request)

    return task


def save_task(request):
    task = request.validated['task']
    try:
        task.validate()
        task.store(request.registry.db, validate=False)
    except ModelValidationError as e:
        for i in e.message:
            request.errors.add('body', i, e.message[i])
        request.errors.status = 422
        return
    except ResourceConflict as e:  # pragma: no cover
        request.errors.add('body', 'data', str(e))
        request.errors.status = 409
        return
    except Exception as e:  # pragma: no cover
        request.errors.add('body', 'data', str(e))
        return
    LOGGER.info('Saved task {} user {} {} {}'.format(task.id, task.user, task.name, task.status),
                extra=context_unpack(request, {'MESSAGE_ID': 'save_task'}, {'RESULT': task.rev}))
    return True


def create_task(request, task_name, run=False):
    task_id = utils.generate_id()
    path = request.path_qs
    path = path.replace(request.registry.route_prefix, '', 1)
    task = Task(dict(
        id=task_id,
        status='new',
        name=task_name,
        date=get_now(),
        user=request.validated['user_token']
    ))
    task.request = ApiRequest(dict(
        method=request.method,
        path=path,
        body=request.body,
    ))
    content_type = request.headers.get('Content-type')
    if content_type and content_type != 'application/json':
        task.request.content_type = content_type
    token = request.headers.get('X-Access-Token')
    if token:
        task.request.acc_token = token
    if run:
        task.dateLastRun = get_now()
    request.validated['task_id'] = task_id
    request.validated['task'] = task
    request.response.headers['X-Task-ID'] = task_id
    params = {'TASK_ID': task.id, 'TASK_USER': task.user}
    utils.update_logging_context(request, params)
    if not save_task(request):
        return
    if run:
        run_task(request, acquired=True)
    return task


def clean_up_doc(doc, service_fields=SERVICE_FIELDS):
    for field in service_fields:
        if field in doc:
            del doc[field]
    return doc


def tender_from_data(request, data, raise_error=True, create=True):
    # FIXME
    if request.registry.dry_run:
        request.registry.dry_run = False
    if data and 'operator' in data:
        data.pop('operator', None)
    return utils.tender_from_data(request, data, raise_error, create)


def extract_tender(request):
    return utils.extract_tender(request)
