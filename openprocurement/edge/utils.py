# -*- coding: utf-8 -*-
import re
from hashlib import md5
from functools import partial
from couchdb.http import ResourceConflict
from cornice.resource import resource, add_view
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
    def wrapper(obj):
        return obj
    return wrapper

utils.opresource = null_decorator
utils.json_view = null_decorator

PKG = get_distribution(__package__)
LOGGER = getLogger(PKG.project_name)
SERVICE_FIELDS = ('__parent__', 'doc_type')
SESSION = Session()

# APIResource = utils.APIResource

# json_view = partial(view, renderer='json')
opresource = partial(resource, error_handler=utils.error_handler, factory=tender_factory)
# eaopresource = partial(resource, error_handler=error_handler, factory=auction_factory)
# contractingresource = partial(resource, error_handler=error_handler, factory=contract_factory)
# planningresource = partial(resource, error_handler=error_handler, factory=plan_factory)


def dry_run(request):
    if request.headers.get('X-Disable-Blade', 0):
        request.response.headers['X-Disable-Blade'] = 'YES'
        return False
    return True


def json_view(**kw):
    """
    Replace view.validators with own smart_validator which knows
    about request.dry_run and can skip validation
    """
    def decorate_validators(validators):
        def smart_validator(request):
            if request.dry_run:
                for validator in validators:
                    validator(request)
        return (smart_validator,)

    def decorate_view(func):
        kw['renderer'] = 'json'
        if 'permission' in kw:
            kw.pop('permission')
        if 'validators' in kw:
            kw['validators'] = decorate_validators(kw['validators'])
        return add_view(func, **kw)
    return decorate_view


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
    item_dateModified = item.get('dateModified') or item.get('date')
    LOGGER.info('Update {} {} {}'.format(item['doc_type'], item['_id'], item_dateModified))
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


def get_bid_url(url, res=None):
    pos = url.find('/bids/')
    if pos < 0 and res:
        url = res.headers.get('Location', '')
        pos = url.find('/bids/')
    if pos < 0:
        return
    pos = url.find('/', pos + 6)
    if pos < 0:
        return url
    return url[:pos]


def set_bid_refs(item, url, user, deleted=False):
    if 'doc_type' not in item:
        item['doc_type'] = 'Bid'
    if 'tender' not in item and url:
        item['tender'] = url.rsplit('/', 3)[1]
    if 'user' not in item and user:
        item['user'] = user
    if deleted:
        item['deleted'] = get_now().isoformat()
    return item


def update_bid_resource(request, url, acc_token, user):
    headers = {'X-Access-Token': acc_token}
    timeout = request.registry.remote_timeout
    try:
        res = SESSION.get(url, headers=headers, timeout=timeout)
        res.raise_for_status()
        item = res.json().get('data')
        if not item:
            raise ValueError('Bad response {}'.format(res.text))
    except Exception as e:
        message = '{}: {}'.format(type(e).__name__, e)
        LOGGER.error('Error update {} failed {}'.format(url, message))
        return
    set_bid_refs(item, url, user)
    return save_resource_item(request.registry.db, item)


def save_bid_resource(request, res, url, user, deleted=False):
    try:
        item = res.json().get('data')
    except (AttributeError, ValueError):
        return
    if not item or not item.get('tenderers'):
        return
    set_bid_refs(item, url, user, deleted)
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


def get_token_id(path):
    return md5(path).hexdigest()


def get_token_path(path):
    return re.sub(r'^.*/api/[^/]+', '', path)


def save_access_token(request, res, user=None):
    try:
        access = res.json().get('access')
    except ValueError:
        return
    if not access or not access.get('token'):
        return
    if not user:
        user = request.validated['user_token']
    path = res.headers.get('Location', '/')
    path = get_token_path(path)
    token_id = get_token_id(path)
    token = Token(dict(
        id=token_id,
        date=get_now(),
        user=user,
        path=path,
        token=access.get('token'),
        transfer=access.get('transfer')
    ))
    return save_token(request, token)


def remote_get(request, response_json=True):
    path = request.path_qs
    path = path.replace(request.registry.route_prefix, '', 1)
    url = request.registry.remote_url + path
    timeout = request.registry.remote_timeout
    headers = {}
    for k in ('X-Access-Token',):
        if k in request.headers:
            headers[k] = request.headers[k]
    res = None
    try:
        res = SESSION.get(url, headers=headers, timeout=timeout)
        if res.status_code == 412 and 'Set-Cookie' in res.headers:
            LOGGER.info('New cookie {}'.format(res.headers['Set-Cookie']))
            res = SESSION.get(url, headers=headers, timeout=timeout)

        request.response.status_code = res.status_code
        request.response.headers['X-Api-Request-ID'] = res.headers.get('X-Request-ID', '')
        request.response.headers['Content-Type'] = res.headers.get('Content-Type', '')

        LOGGER.info('API_GET {} {} {} {}'.format(url, res.status_code,
                    len(res.text), res.headers.get('X-Request-ID')))
    except Exception as e:
        message = '{}: {}'.format(type(e).__name__, e)
        request.errors.add('body', 'api', message)
        request.response.status_code = 504
        return

    if not res:
        return
    if response_json:
        try:
            return res.json()
        except:
            pass
    return res.text


def run_task(request, acquired=False):
    task = request.validated['task']
    if not acquired:
        task.acquired = get_now()
        if not save_task(request):
            return

    if task.status == 'success' or task.response:
        LOGGER.error('Can\'t run task twice {} status {}'.format(task.id, task.status))
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
    res = None

    try:
        method = task.request.method
        if method not in ('POST', 'PUT', 'PATCH', 'DELETE'):
            raise ValueError('Bad method {}'.format(method))
        data = task.request.body or ''

        res = SESSION.request(method, url, data=data, headers=headers, timeout=timeout)
        if res.status_code == 412 and 'Set-Cookie' in res.headers:
            LOGGER.info('New cookie {}'.format(res.headers['Set-Cookie']))
            res = SESSION.request(method, url, data=data, headers=headers, timeout=timeout)

        request.response.headers['X-Api-Request-ID'] = res.headers.get('X-Request-ID', '')
        task_res = ApiResponse().from_response(res)

        if res.status_code < 400:
            task.status = 'success'
            task.response = task_res
        else:
            task.append_error(task_res)

        LOGGER.info('API_{} {} {} {} {} {}'.format(method, url, len(data), res.status_code,
                    len(res.text), res.headers.get('X-Request-ID')))
    except Exception as e:
        message = "{}: {}".format(type(e).__name__, e)
        task.append_error(dict(body=message))
        LOGGER.error('Error run task {} failed {}'.format(task.id, message))

    if task.status == 'error' and len(task.errors) >= request.registry.remote_retry:
        task.status = 'failed'

    # utils.update_logging_context(request, {'TASK_STATUS': task.status})
    # LOGGER.info('Run task {} {} -> {}'.format(task.id, task.request, task.status),
    #            extra=context_unpack(request, {'MESSAGE_ID': 'run_task'}, {'RESULT': task.status}))

    if not save_task(request):
        return

    if res and res.text:  # task.status == 'success'
        if '"access"' in res.text:
            save_access_token(request, res, task.user)
        if '/bids' in url:
            bid_url = get_bid_url(url, res)
            bid_delete = (method == 'DELETE') and (res.status_code == 200)
            bid_saved = save_bid_resource(request, res, bid_url, task.user, bid_delete)
            if not bid_saved:
                acc_token = headers.get('X-Access-Token')
                update_bid_resource(request, bid_url, acc_token, task.user)
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
        task.acquired = get_now()
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


def load_tender_bid(request, data):
    if not request.dry_run:
        return
    match = re.search(r'/tenders/(?P<tender_id>\w+)/bids/(?P<bid_id>\w+)', request.path)
    user_token = request.validated.get('user_token', None)
    acc_token = request.validated.get('acc_token', None)
    if not match or not user_token or not acc_token:
        return
    tender_id = match.group('tender_id')
    bid_id = match.group('bid_id')
    token_path = get_token_path(get_bid_url(request.path))
    token_id = get_token_id(token_path)
    db = request.registry.db
    token = db.get(token_id)
    if not token or token.get('doc_type') != 'Token':
        request.errors.add('body', 'token', 'Not found')
        return
    if token.get('user') != user_token:
        request.errors.add('body', 'token', 'Bad user')
        return
    if acc_token and token['token'] != acc_token:
        request.errors.add('body', 'token', 'Bad token')
        return
    bid = db.get(bid_id)
    if not bid or bid.get('doc_type') != 'Bid' or bid.get('deleted'):
        request.errors.add('body', 'bid', 'Not found')
        return
    if bid.get('user') != user_token:
        request.errors.add('body', 'bid', 'Bad user')
        return
    if bid.get('tender') != tender_id:
        request.errors.add('body', 'bid', 'Bad tender')
        return
    for k in ('_id', '_rev', 'doc_type', 'tender', 'user'):
        bid.pop(k, None)
    if not data.get('bids', None):
        data['bids'] = []
    data['bids'].append(bid)
    # FIXME
    request.authenticated_role = 'bid_owner'


def load_access_tokens(request):
    acc_token = request.params.get('acc_token')
    if not acc_token:
        acc_token = request.headers.get('X-Access-Token')
    if acc_token and len(acc_token) > 30:
        request.validated['acc_token'] = acc_token
    user_token = request.params.get('user_token')
    if not user_token:
        user_token = request.headers.get('X-User-Token')
    if user_token and len(user_token) > 30:
        request.validated['user_token'] = user_token


def tender_from_data(request, data, raise_error=True, create=True):
    load_access_tokens(request)
    if '/bids/' in request.path and not data.get('bids', None):
        load_tender_bid(request, data)
    if 'operator' in data:
        data.pop('operator', None)
    return utils.tender_from_data(request, data, raise_error, create)


def extract_tender(request):
    if request.registry.dry_run:
        request.registry.dry_run = False
    return utils.extract_tender(request)
