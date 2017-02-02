# -*- coding: utf-8 -*-
from openprocurement.edge.utils import opresource, json_view, create_task, remote_get
from openprocurement.api.views import bid
from openprocurement.api.validation import (
    validate_bid_data,
    validate_patch_bid_data,
)


@opresource(name='Tender Bids',
            collection_path='/tenders/{tender_id}/bids',
            path='/tenders/{tender_id}/bids/{bid_id}',
            procurementMethodType='belowThreshold',
            description="Tender bids")
class TenderBidResource(bid.TenderBidResource):
    """
    Create, update and remove bids for tenders
    """

    @json_view(content_type="application/json", permission='create_bid', validators=(validate_bid_data,))
    def collection_post(self):
        if self.request.dry_run:
            self.request.registry.dry_run = True  # disable save_tender
            res = super(TenderBidResource, self).collection_post()
            if len(self.request.errors):
                return res

        task = create_task(self.request, 'tender.bid.create', run=True)
        if task.status != 'success':
            self.request.response.status_code = 102
            return
        self.request.response.status_code = task.response.status_code
        self.request.response.headers['Location'] = task.get_location()
        return task.response_json()

    @json_view(permission='view_tender')
    def collection_get(self):
        if self.request.dry_run:
            return super(TenderBidResource, self).collection_get()
        return remote_get(self.request)

    @json_view(permission='view_tender')
    def get(self):
        if self.request.dry_run:
            return super(TenderBidResource, self).get()
        return remote_get(self.request)

    @json_view(content_type="application/json", permission='edit_bid', validators=(validate_patch_bid_data,))
    def patch(self):
        if self.request.dry_run:
            self.request.registry.dry_run = True  # disable save_tender
            res = super(TenderBidResource, self).patch()
            if len(self.request.errors):
                return res

        task = create_task(self.request, 'tender.bid.edit', run=True)
        self.request.response.status_code = task.last_status_code()
        return task.response_json()

    @json_view(permission='edit_bid')
    def delete(self):
        task = create_task(self.request, 'tender.bid.delete', run=True)
        self.request.response.status_code = task.last_status_code()
        return task.response_json()
