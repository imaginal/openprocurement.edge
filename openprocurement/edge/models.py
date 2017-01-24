# -*- coding: utf-8 -*-
import json
from couchdb_schematics.document import SchematicsDocument
from zope.interface import implementer, Interface
from schematics.types import (StringType, FloatType, IntType, URLType,
    BooleanType, BaseType, EmailType, MD5Type)
from schematics.types.compound import ModelType
from schematics.types.serializable import serializable
from openprocurement.api.models import (Model, ListType, IsoDateTimeType,
    get_now, schematics_default_role)


class ApiRequest(Model):

    method = StringType(choices=['POST', 'PUT', 'PATCH', 'DELETE'], required=True)
    path = StringType(required=True)
    body = StringType()
    acc_token = StringType()
    content_type = StringType()

    def __str__(self):
        return '{} {}'.format(self.method, self.path)


class ApiResponse(Model):

    date = IsoDateTimeType(required=True)
    status_code = IntType()
    location = StringType()
    requestID = StringType()
    body = StringType()

    def __str__(self):
        return '{} {}'.format(self.status_code, self.requestID)

    def from_response(self, res):
        if not self.date:
            self.date = get_now()
        self.status_code = res.status_code
        if res.headers.get('Location'):
            self.location = res.headers['Location']
        if res.headers.get('X-Request-ID'):
            self.requestID = res.headers['X-Request-ID']
        self.body = res.text
        return self


class ITask(Interface):
    """ Base task interface """


@implementer(ITask)
class Task(SchematicsDocument, Model):
    """Data regarding any planed api call."""
    class Options:
        roles = {
            'default': schematics_default_role,
        }

    date = IsoDateTimeType(required=True)
    name = StringType(required=True)
    user = StringType(required=True)
    status = StringType(choices=['new', 'success', 'error', 'failed'], default='new')
    request = ModelType(ApiRequest, required=True)
    acquired = IsoDateTimeType()
    response = ModelType(ApiResponse)
    errors = ListType(ModelType(ApiResponse))

    def get_role(self):
        return 'default'

    def __repr__(self):
        return '<%s:%r@%r>' % (type(self).__name__, self.id, self.rev)

    def initialize(self):
        self.date = get_now()

    @serializable(serialized_name='id')
    def doc_id(self):
        """A property that is serialized by schematics exports."""
        return self._id

    def append_error(self, response, set_status='error'):
        if isinstance(response, dict):
            response = ApiResponse(response)
        if response.date is None:
            response.date = get_now()
        if set_status:
            self.status = set_status
        if self.errors is None:
            self.errors = list()
        self.errors.append(response)

    def response_json(self):
        if self.response:
            try:
                return json.loads(self.response.body)
            except ValueError:
                return self.response.body
        if self.errors:
            last_error = self.errors[-1]
            try:
                return json.loads(last_error.body)
            except ValueError:
                return last_error.body
        return

    def last_status_code(self, default_error=502):
        if self.response and self.response.status_code:
            return self.response.status_code
        elif self.errors and self.errors[-1].status_code:
            return self.errors[-1].status_code
        elif self.errors:
            return default_error
        return

    def import_data(self, raw_data, **kw):
        """ Converts and imports the raw data into the instance of the model
            according to the fields in the model."""
        data = self.convert(raw_data, **kw)
        for k, v in data.items():
            default = self.__class__.fields[k].default
            if v == default or v == getattr(self, k):
                del data[k]
        self._data.update(data)
        return self


class IToken(Interface):
    """ Base access token interface """


@implementer(IToken)
class Token(SchematicsDocument, Model):
    """Data regarding any planed api call."""
    class Options:
        roles = {
            'default': schematics_default_role,
        }

    date = IsoDateTimeType()
    user = StringType(required=True)
    path = StringType()
    token = StringType()
    transfer = StringType()

    def get_role(self):
        return 'default'

    def __repr__(self):
        return '<%s:%r@%r>' % (type(self).__name__, self.id, self.rev)

    def initialize(self):
        self.date = get_now()

    @serializable(serialized_name='id')
    def doc_id(self):
        """A property that is serialized by schematics exports."""
        return self._id

    def import_data(self, raw_data, **kw):
        """ Converts and imports the raw data into the instance of the model
            according to the fields in the model."""
        data = self.convert(raw_data, **kw)
        for k, v in data.items():
            default = self.__class__.fields[k].default
            if v == default or v == getattr(self, k):
                del data[k]
        self._data.update(data)
        return self
