# -*- coding: utf-8 -*-
from openprocurement.edge.utils import json_view, opresource, create_task
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

    @json_view(content_type="application/json", validators=(validate_bid_data,))
    def collection_post(self):
        self.request.registry.dry_run = True
        res = super(TenderBidResource, self).collection_post()
        if self.request.response.status_code != 201:
            return res
        task = create_task(self.request, 'tender.bid.create', run=True)
        if task.status != 'success':
            self.request.response.status_code = 102
            return
        self.request.response.status_code = task.response.status_code
        self.request.response.headers['Location'] = str(task.response.location)
        return task.response_json()

    @json_view(content_type="application/json", validators=(validate_patch_bid_data,))
    def patch(self):
        task = create_task(self.request, 'tender.bid.edit', run=True)
        self.request.response.status_code = task.last_status_code()
        return task.response_json()

    @json_view()
    def delete(self):
        task = create_task(self.request, 'tender.bid.delete', run=True)
        self.request.response.status_code = task.last_status_code()
        return task.response_json()
