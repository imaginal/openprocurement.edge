# -*- coding: utf-8 -*-
from pyramid.security import (
    ALL_PERMISSIONS,
    Allow,
    Everyone,
)
from openprocurement.api.traversal import Root, factory
Root.__acl__.insert(0, (Allow, Everyone, ALL_PERMISSIONS))


def tender_factory(request):
    user_token = request.params.get('user_token')
    if not user_token:
        user_token = request.headers.get('X-User-Token')
    request.validated['user_token'] = user_token
    if 'bid_id' in request.matchdict:
        del request.matchdict['bid_id']
    return factory(request)
