# -*- coding: utf-8 -*-
from pyramid.security import (
    ALL_PERMISSIONS,
    Allow,
    Everyone,
)
from openprocurement.api.traversal import Root, factory
Root.__acl__.insert(0, (Allow, Everyone, ALL_PERMISSIONS))


def tender_factory(request):
    if not request.dry_run:
        return Root(request)
    return factory(request)
