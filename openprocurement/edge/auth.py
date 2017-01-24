# -*- coding: utf-8 -*-
from openprocurement.api import auth


class AuthenticationPolicy(auth.AuthenticationPolicy):
    pass


def authenticated_role(request):
    return 'Administrator'


def check_accreditation(request, level):
    return level != 't'
