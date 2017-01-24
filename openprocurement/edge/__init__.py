# -*- coding: utf-8 -*-
"""Main entry point
"""
if 'test' not in __import__('sys').argv[0]:
    import gevent.monkey
    gevent.monkey.patch_all()
import os
from couchdb import Server as CouchdbServer, Session
from couchdb.http import Unauthorized, extract_credentials
from libnacl.sign import Signer, Verifier
from openprocurement.edge.auth import AuthenticationPolicy, authenticated_role, check_accreditation
from openprocurement.edge.utils import opresource, extract_tender, tender_from_data

from openprocurement.api.design import sync_design
from openprocurement.api.models import Tender
from openprocurement.api.utils import (forbidden, isTender, request_params, set_renderer,
    register_tender_procurementMethodType, beforerender, add_logging_context, set_logging_context)

#from pyramid.authorization import ACLAuthorizationPolicy as AuthorizationPolicy
from pyramid.config import Configurator
from pyramid.events import NewRequest, BeforeRender, ContextFound
from pyramid.renderers import JSON, JSONP
from pyramid.settings import asbool
from logging import getLogger

LOGGER = getLogger("{}.init".format(__name__))
SECURITY = {u'admins': {u'names': [], u'roles': ['_admin']}, u'members': {u'names': [], u'roles': ['_admin']}}
VALIDATE_DOC_ID = '_design/_auth'
VALIDATE_DOC_UPDATE = """function(newDoc, oldDoc, userCtx){
    if(newDoc._deleted && newDoc.tenderID) {
        throw({forbidden: 'Not authorized to delete this document'});
    }
    if(userCtx.roles.indexOf('_admin') !== -1 && newDoc._id.indexOf('_design/') === 0) {
        return;
    }
    if(userCtx.name === '%s') {
        return;
    } else {
        throw({forbidden: 'Only authorized user may edit the database'});
    }
}"""


class Server(CouchdbServer):
    _uuid = None

    @property
    def uuid(self):
        """The uuid of the server.

        :rtype: basestring
        """
        if self._uuid is None:
            _, _, data = self.resource.get_json()
            self._uuid = data['uuid']
        return self._uuid


def main(global_config, **settings):
    version = settings.get('api_version')
    route_prefix = '/api/{}'.format(version)
    config = Configurator(
        autocommit=True,
        settings=settings,
        # authentication_policy=AuthenticationPolicy(settings['auth.file'], __name__),
        # authorization_policy=AuthorizationPolicy(),
        route_prefix=route_prefix,
    )
    config.include('pyramid_exclog')
    config.include("cornice")
    config.add_forbidden_view(forbidden)
    config.add_request_method(request_params, 'params', reify=True)
    config.add_request_method(authenticated_role, reify=True)
    config.add_request_method(extract_tender, 'tender', reify=True)
    config.add_request_method(check_accreditation)
    config.add_renderer('prettyjson', JSON(indent=4))
    config.add_renderer('jsonp', JSONP(param_name='opt_jsonp'))
    config.add_renderer('prettyjsonp', JSONP(indent=4, param_name='opt_jsonp'))
    config.add_subscriber(add_logging_context, NewRequest)
    config.add_subscriber(set_logging_context, ContextFound)
    config.add_subscriber(set_renderer, NewRequest)
    config.add_subscriber(beforerender, BeforeRender)
    config.scan("openprocurement.edge.views.spore")
    config.scan("openprocurement.edge.views.health")

    # tender procurementMethodType plugins support
    config.add_route_predicate('procurementMethodType', isTender)
    config.registry.tender_procurementMethodTypes = {}
    config.add_request_method(tender_from_data)
    config.add_directive('add_tender_procurementMethodType', register_tender_procurementMethodType)

    config.add_tender_procurementMethodType(Tender)
    config.scan("openprocurement.edge.views.tenders")
    config.scan("openprocurement.edge.views.bid")

    # CouchDB connection
    db_name = os.environ.get('DB_NAME', settings['couchdb.db_name'])
    server = Server(settings.get('couchdb.url'), session=Session(retry_delays=range(10)))
    if 'couchdb.admin_url' not in settings and server.resource.credentials:
        try:
            server.version()
        except Unauthorized:
            server = Server(extract_credentials(settings.get('couchdb.url'))[0])
    config.registry.couchdb_server = server

    if db_name not in server:
        server.create(db_name)
    db = server[db_name]
    # sync couchdb views
    sync_design(db)
    config.registry.db = db

    config.registry.route_prefix = route_prefix
    config.registry.remote_url = settings.get('remote.url')
    config.registry.remote_key = settings.get('remote.key')
    config.registry.remote_timeout = float(settings.get('remote.timeout', 10))
    config.registry.remote_retry = int(settings.get('remote.retry', 10))

    if config.registry.remote_url.find('/api/') < 0:    # append /api/version if missed
        config.registry.remote_url += route_prefix

    config.registry.server_id = settings.get('id', '')
    config.registry.health_threshold = float(settings.get('health_threshold', 99))
    config.registry.update_after = asbool(settings.get('update_after', True))
    config.registry.dry_run = asbool(settings.get('dry_run', False))
    config.registry.api_version = version
    return config.make_wsgi_app()
