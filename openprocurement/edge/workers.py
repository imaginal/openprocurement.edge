# -*- coding: utf-8 -*-
from gevent import monkey
monkey.patch_all()

import logging
import logging.config
import time
import os
from datetime import datetime
from gevent import Greenlet
from gevent import spawn, sleep
from gevent.queue import Empty
from iso8601 import parse_date
from pytz import timezone
from couchdb import http
from openprocurement.edge.utils import make_patch
from requests.exceptions import ConnectionError
from openprocurement_client.exceptions import (
    InvalidResponse,
    RequestFailed,
    ResourceNotFound,
    ResourceGone
)

logger = logging.getLogger(__name__)

TZ = timezone(os.environ['TZ'] if 'TZ' in os.environ else 'Europe/Kiev')


class ResourceItemWorker(Greenlet):

    def __init__(self, api_clients_queue=None, resource_items_queue=None,
                 db=None, dbs=None, config_dict=None, retry_resource_items_queue=None,
                 api_clients_info=None):
        Greenlet.__init__(self)
        self.exit = False
        self.update_doc = False
        self.db = db
        self.dbs = dbs
        self.config = config_dict
        self.archive = len(dbs)
        self.archive_status = self.config['archive_status']
        if self.archive_status and ',' in self.archive_status:
            self.archive_status = self.archive_status.strip().split(',')
        self.delete_from_archive = self.config.get('delete_from_archive')
        self.exists_in_archive = {}
        self.api_clients_queue = api_clients_queue
        self.resource_items_queue = resource_items_queue
        self.retry_resource_items_queue = retry_resource_items_queue
        self.bulk = {}
        self.priority_cache = {}
        self.bulk_save_limit = self.config['bulk_save_limit']
        self.bulk_save_interval = self.config['bulk_save_interval']
        self.start_time = datetime.now()
        self.api_clients_info = api_clients_info

    def add_to_retry_queue(self, resource_item_id, priority=0, status_code=0):
        retries_count = priority - 1000 if priority >= 1000 else priority
        if retries_count > self.config['retries_count'] and status_code != 429:
            logger.critical(
                '{} {} reached limit retries count {} and droped from '
                'retry_queue.'.format(
                    self.config['resource'][:-1].title(),
                    resource_item_id, self.config['retries_count']),
                extra={'MESSAGE_ID': 'dropped_documents'}
            )
            return
        timeout = 0
        if status_code != 429:
            timeout = self.config['retry_default_timeout'] * retries_count
            priority += 1
        sleep(timeout)
        self.retry_resource_items_queue.put((priority, resource_item_id))
        logger.info(
            'Put to \'retry_queue\' {}: {}'.format(
                self.config['resource'][:-1], resource_item_id
            ),
            extra={'MESSAGE_ID': 'add_to_retry'}
        )

    def _get_api_client_dict(self):
        if not self.api_clients_queue.empty():
            try:
                api_client_dict = self.api_clients_queue.get(
                    timeout=self.config['queue_timeout']
                )
            except Empty:
                return None
            if self.api_clients_info[api_client_dict['id']]['drop_cookies']:
                try:
                    api_client_dict['client'].renew_cookies()
                    self.api_clients_info[api_client_dict['id']] = {
                        'drop_cookies': False,
                        'request_durations': {},
                        'request_interval': 0,
                        'avg_duration': 0
                    }
                    api_client_dict['request_interval'] = 0
                    api_client_dict['not_actual_count'] = 0
                    logger.info('Drop lazy api_client {} cookies'.format(
                        api_client_dict['id']))
                except (Exception, ConnectionError) as e:
                    self.api_clients_queue.put(api_client_dict)
                    logger.debug('PUT API CLIENT: {}'.format(api_client_dict['id']),
                                 extra={'MESSAGE_ID': 'put_client'})
                    logger.error('While renewing cookies catch exception: '
                                 '{}'.format(e.message))
                    return None
            logger.debug(
                'GET API CLIENT: {} {} with requests interval: {}'.format(
                    api_client_dict['id'],
                    api_client_dict['client'].session.headers['User-Agent'],
                    api_client_dict['request_interval']
                ),
                extra={
                    'MESSAGE_ID': 'get_client',
                    'REQUESTS_TIMEOUT': api_client_dict['request_interval']
                }
            )
            sleep(api_client_dict['request_interval'])
            return api_client_dict
        else:
            return None

    def _get_resource_item_from_queue(self):
        if not self.resource_items_queue.empty():
            priority, resource_item_id = self.resource_items_queue.get(
                timeout=self.config['queue_timeout'])
            logger.debug('Get {} {} from main queue.'.format(
                self.config['resource'][:-1], resource_item_id))
            return priority, resource_item_id
        else:
            return None, None

    def _get_resource_item_from_public(self, api_client_dict, priority,
                                       resource_item_id):
        try:
            logger.debug('Request interval {} sec. for client {}'.format(
                api_client_dict['request_interval'],
                api_client_dict['client'].session.headers['User-Agent']),
                extra={'REQUESTS_TIMEOUT': api_client_dict['request_interval']})
            start = time.time()
            public_resource_item = api_client_dict['client'].get_resource_item(
                resource_item_id).get('data')
            self.api_clients_info[api_client_dict['id']][
                'request_durations'][datetime.now()] = time.time() - start
            self.api_clients_info[api_client_dict['id']]['request_interval'] =\
                api_client_dict['request_interval']
            logger.debug('Recieved from API {}: {} {}'.format(
                self.config['resource'][:-1], public_resource_item['id'],
                public_resource_item['dateModified'])
            )
            if api_client_dict['request_interval'] > 0:
                api_client_dict['request_interval'] -=\
                    self.config['client_dec_step_timeout']
            self.api_clients_queue.put(api_client_dict)
            logger.debug('PUT API CLIENT: {}'.format(api_client_dict['id']),
                         extra={'MESSAGE_ID': 'put_client'})
            return public_resource_item
        except ResourceGone:
            self.api_clients_queue.put(api_client_dict)
            logger.debug('PUT API CLIENT: {}'.format(api_client_dict['id']),
                         extra={'MESSAGE_ID': 'put_client'})
            logger.info(
                '{} {} archived.'.format(self.config['resource'][:-1].title(),
                                         resource_item_id)
            )
            return None  # Archived
        except InvalidResponse as e:
            self.api_clients_info[api_client_dict['id']][
                'request_durations'][datetime.now()] = time.time() - start
            self.api_clients_info[api_client_dict['id']]['request_interval'] =\
                api_client_dict['request_interval']
            self.api_clients_queue.put(api_client_dict)
            logger.debug('PUT API CLIENT: {}'.format(api_client_dict['id']),
                         extra={'MESSAGE_ID': 'put_client'})
            logger.error(
                'Error while getting {} {} from public with status code: '
                '{}'.format(
                    self.config['resource'][:-1], resource_item_id,
                    e.status_code), extra={'MESSAGE_ID': 'exceptions'})
            self.add_to_retry_queue(resource_item_id, priority=priority)
            return None
        except RequestFailed as e:
            self.api_clients_info[api_client_dict['id']][
                'request_durations'][datetime.now()] = time.time() - start
            self.api_clients_info[api_client_dict['id']]['request_interval'] =\
                api_client_dict['request_interval']
            if e.status_code == 429:
                if (api_client_dict['request_interval'] >
                        self.config['drop_threshold_client_cookies']):
                    api_client_dict['client'].session.cookies.clear()
                    api_client_dict['request_interval'] = 0
                else:
                    api_client_dict['request_interval'] +=\
                        self.config['client_inc_step_timeout']
                self.api_clients_queue.put(
                    api_client_dict, timeout=api_client_dict['request_interval']
                )
                logger.warning(
                    'PUT API CLIENT: {} after {} sec.'.format(
                        api_client_dict['id'],
                        api_client_dict['request_interval']),
                    extra={'MESSAGE_ID': 'put_client'})
            else:
                self.api_clients_queue.put(api_client_dict)
                logger.debug('PUT API CLIENT: {}'.format(api_client_dict['id']),
                             extra={'MESSAGE_ID': 'put_client'})
            logger.error(
                'Request failed while getting {} {} from public with status '
                'code {}: '.format(
                    self.config['resource'][:-1], resource_item_id,
                    e.status_code), extra={'MESSAGE_ID': 'exceptions'})
            self.add_to_retry_queue(
                resource_item_id, priority=priority, status_code=e.status_code
            )
            return None  # request failed
        except ResourceNotFound as e:
            self.api_clients_info[api_client_dict['id']][
                'request_durations'][datetime.now()] = time.time() - start
            self.api_clients_info[api_client_dict['id']]['request_interval'] =\
                api_client_dict['request_interval']
            logger.error('Resource not found {} at public: {}. {}'.format(
                self.config['resource'][:-1], resource_item_id, e.message),
                extra={'MESSAGE_ID': 'not_found_docs'})
            api_client_dict['client'].session.cookies.clear()
            logger.info('Clear client cookies')
            self.add_to_retry_queue(resource_item_id, priority=priority)
            self.api_clients_queue.put(api_client_dict)
            logger.debug('PUT API CLIENT: {}'.format(api_client_dict['id']),
                         extra={'MESSAGE_ID': 'put_client'})
            return None  # not found
        except Exception as e:
            self.api_clients_info[api_client_dict['id']][
                'request_durations'][datetime.now()] = time.time() - start
            self.api_clients_info[api_client_dict['id']]['request_interval'] =\
                api_client_dict['request_interval']
            self.api_clients_queue.put(api_client_dict)
            logger.debug('PUT API CLIENT: {}'.format(api_client_dict['id']),
                         extra={'MESSAGE_ID': 'put_client'})
            logger.error(
                'Error while getting resource item {} {} from public '
                '{}: '.format(
                    self.config['resource'][:-1], resource_item_id,
                    e.message),
                extra={'MESSAGE_ID': 'exceptions'})
            self.add_to_retry_queue(resource_item_id, priority=priority)
            return None

    def _add_to_bulk(self, local_resource_item, public_resource_item, priority):
        public_resource_item['doc_type'] = self.config['resource'][:-1].title()
        public_resource_item['_id'] = public_resource_item['id']
        if local_resource_item:
            if local_resource_item['dateModified'] >= public_resource_item['dateModified']:
                logger.debug('Ignored dublicate {} {} existing {}, current '
                    '{}'.format(
                        self.config['resource'][:-1], public_resource_item['id'],
                        local_resource_item['dateModified'],
                        public_resource_item['dateModified']),
                    extra={'MESSAGE_ID': 'skipped'})
                return
            public_resource_item['_rev'] = local_resource_item['_rev']
            changes = local_resource_item.pop('changes', [])
            patch = make_patch(public_resource_item, local_resource_item)
            if patch and patch.patch:
                changes.insert(0, patch.patch)
            public_resource_item['changes'] = changes
        bulk_doc = self.bulk.get(public_resource_item['id'])

        if bulk_doc and bulk_doc['dateModified'] < \
                public_resource_item['dateModified']:
            logger.debug(
                'Replaced {} in bulk {} previous {}, current {}'.format(
                    self.config['resource'][:-1], bulk_doc['id'],
                    bulk_doc['dateModified'],
                    public_resource_item['dateModified']),
                extra={'MESSAGE_ID': 'skipped'})
            self.bulk[public_resource_item['id']] = public_resource_item
            if priority < self.priority_cache[public_resource_item['id']]:
                self.priority_cache[public_resource_item['id']] = priority
        elif bulk_doc and bulk_doc['dateModified'] >=\
                public_resource_item['dateModified']:
            logger.debug(
                'Ignored dublicate {} {} in bulk: previous {}, current '
                '{}'.format(
                    self.config['resource'][:-1], public_resource_item['id'],
                    bulk_doc['dateModified'],
                    public_resource_item['dateModified']),
                extra={'MESSAGE_ID': 'skipped'})
        if not bulk_doc:
            self.bulk[public_resource_item['id']] = public_resource_item
            self.priority_cache[public_resource_item['id']] = priority
            logger.debug('Put in bulk {} {} {}'.format(
                    self.config['resource'][:-1],
                    public_resource_item['id'],
                    public_resource_item['dateModified']
                ),
                extra={'MESSAGE_ID': 'add_to_save_bulk'})

    def sync_archive_dbs(self):
        logger.info('Start check {} archive and main db.'
            .format(self.config['resource']),
            extra={'MESSAGE_ID': 'start_sync_archive'})
        try:
            for year in sorted(self.dbs.keys()):
                if self._check_sync_needed(year):
                    logger.warning('Need sync archive {} and main db'.format(year))
                    self._sync_main_from_archive(year)
        except Exception as e:
            logger.error('Error when sync archive {} and main: '
                '{} {}'.format(year, type(e).__name__, e.message))
            raise
        logger.info('End check {} archive and main db.'
            .format(self.config['resource']),
            extra={'MESSAGE_ID': 'end_sync_archive'})

    def _check_sync_needed(self, year, limit=50):
        logger.info('Check sync {} archive {} and main db...'
            .format(self.config['resource'], year),
            extra={'MESSAGE_ID': 'check_sync_archive'})
        main_db = self.db
        archive_db = self.dbs[year]
        view_path = '_all_docs'
        docs_to_check = {}
        # collect some documents to check
        for doc in archive_db.view(view_path, limit=limit):
            if doc['id'][:1] != '_':
                docs_to_check[doc['id']] = doc
        for doc in archive_db.view(view_path, limit=limit, descending=True):
            if doc['id'][:1] != '_':
                docs_to_check[doc['id']] = doc
        if not docs_to_check:
            return False
        # find same docs in main db, stop on first not found or deleted
        for doc in main_db.view(view_path, keys=docs_to_check.keys()):
            if not doc.get('value') or doc['value'].get('deleted'):
                logger.error('Stub for {} {} from archive {} not found in main db'
                    .format(self.config['resource'][:-1], doc.get('id'), year))
                return True
            docs_to_check.pop(doc['id'])
        for doc_id in docs_to_check:
            logger.error('Stub for {} {} from archive {} not found in main db'
                .format(self.config['resource'][:-1], doc_id, year))
            return True
        return False

    def _sync_main_from_archive(self, year):
        logger.info('Start sync {} from archive {} to main db...'
            .format(self.config['resource'], year),
            extra={'MESSAGE_ID': 'start_sync_archive'})
        archive_db = self.dbs[year]
        view_path = '_design/{}/_view/by_dateModified'.format(
            self.config['resource'])
        self.stub_created = 0
        self.stub_skipped = 0
        count_rows = 0
        rows_bulk = {}
        stat_time = time.time()
        view_results = archive_db.view(view_path)
        for row in view_results:
            count_rows += 1
            # print some statistics
            if time.time() - stat_time > self.config.get('sync_main_stat', 30):
                total_rows = view_results.total_rows
                p = round(100.0 * count_rows / total_rows, 1)
                logger.info('Sync {} archive {} to main: {:,} created, {:,} '
                    'skipped, {:.1f}%'.format(self.config['resource'][:-1],
                        year, self.stub_created, self.stub_skipped, p),
                    extra={'MESSAGE_ID': 'sync_archive_progress'})
                stat_time = time.time()
            # process rows
            rows_bulk[row.id] = row
            self._check_main_bulk(rows_bulk, year)
        # flush leftovers
        if rows_bulk:
            self._check_main_bulk(rows_bulk, year, limit=0)
            assert not rows_bulk, 'Bulk is not empty on exit'
        if self.bulk:
            self._save_bulk_docs(flush=True)
            assert not self.bulk, 'Bulk is not empty on exit'
        logger.info('End sync {} archive {} to main: {:,} created, {:,} skipped'
            .format(self.config['resource'][:-1], year,
                self.stub_created, self.stub_skipped),
            extra={'MESSAGE_ID': 'end_sync_archive'})

    def _check_main_bulk(self, archive_rows, year, limit=100):
        if len(archive_rows) < limit:
            return
        # check by dates
        main_db = self.db
        view_path = '_design/{}/_view/by_dateModified'.format(
            self.config['resource'])
        archive_dates = [r['key'] for r in archive_rows.values()]
        for n in range(5):
            try:
                view_rows = main_db.view(view_path, keys=archive_dates)
                break
            except Exception as e:
                logger.error('Error bulk check {} by_dateModified in main: {} (try {})'
                    .format(self.config['resource'], e.message, n + 1))
                if n > 3:
                    raise
                sleep(1 + 2 * n)
        # remove from queue existing stubs with same dateModified
        for row in view_rows:
            archive_rows.pop(row['id'])
            self.stub_skipped += 1
        if len(archive_rows) < limit:
            return
        # check other revisions
        view_path = '_all_docs'
        archive_ids = archive_rows.keys()
        for n in range(5):
            try:
                view_rows = main_db.view(view_path, keys=archive_ids)
                break
            except Exception as e:
                logger.error('Error bulk check {} _all_docs in main: {} (try {})'
                    .format(self.config['resource'], e.message, n + 1))
                if n > 3:
                    raise
                sleep(1 + 2 * n)
        # rows withought values is not found
        stub_revs = {}
        for r in view_rows:
            if r.get('value'):
                stub_revs[r['id']] = r['value']['rev']
        # add to bulk
        for doc_id, row in archive_rows.items():
            logger.debug('Add stub from archive {} to main {} {}'
                .format(year, self.config['resource'][:-1], doc_id),
                extra={'MESSAGE_ID': 'add_stub_from_archive'})
            try:
                new_stub = self._get_stub_from_view_row(row, year)
            except Exception as e:
                logger.error('Error creating stub from row {} {} {}'
                    .format(row, type(e).__name__, e.message))
                archive_doc = self._get_archive_doc(year, doc_id)
                new_stub = self._get_archive_stub(archive_doc)
            # check for existing stub
            if doc_id in stub_revs:
                new_stub['_rev'] = stub_revs[doc_id]
            # add new stub to bulk
            self.stub_created += 1
            self.bulk[doc_id] = new_stub
            self.priority_cache[doc_id] = 1
            self._save_bulk_docs()
        # clear
        archive_rows.clear()

    def _run_sync_worker(self):
        for n in range(10):
            try:
                return self._sync_main_to_archive()
            except Exception as e:
                logger.error('Error in sync archive worker: {} {} (try {})'
                    .format(type(e).__name__, e.message, n + 1),
                    extra={'MESSAGE_ID': 'sync_worker_failed'})
                if n == 9:
                    raise
                if self.exit:
                    return
                sleep(self.config.get('sync_worker_error_sleep', 30))

    def _sync_main_to_archive(self):
        logger.info('Start sync from {} main to archive worker...'
            .format(self.config['resource']),
            extra={'MESSAGE_ID': 'start_sync_worker'})
        self.sync_archive_priority = 1
        main_db = self.db
        view_path = '_design/{}/_view/by_dateModified'.format(
            self.config['resource'])
        bulk_archive = {k: {} for k in self.dbs}
        rows_count = 0
        archive_count = 0
        stat_time = time.time()
        view_results = main_db.view(view_path, descending=True)
        for row in view_results:
            if self.exit:
                break
            # some statistics
            rows_count += 1
            if time.time() - stat_time > self.config['sync_worker_stat']:
                total_rows = view_results.total_rows
                p = round(100.0 * rows_count / total_rows, 1)
                logger.info('Sync {} worker: {:,} processed {:,} in archive {:.1f}%'
                    .format(self.config['resource'], rows_count, archive_count, p),
                    extra={'MESSAGE_ID': 'sync_worker_timer'})
                sleep(self.config['sync_worker_sleep'])
                stat_time = time.time()
            # process rows
            doc_id = row['id']
            doc = row['value']
            if 'archived' in doc:  # is archive stub
                year = self._get_archive_year(doc)
                if year not in self.dbs:
                    logger.error('No archive for {} {} {}'
                        .format(year, self.config['resource'][:-1], doc_id),
                        extra={'MESSAGE_ID': 'archive_not_found'})
                    continue
                bulk_archive[year][doc_id] = row['key']
                self._check_archive_bulk(bulk_archive, year)
                archive_count += 1
        # flush
        for year in sorted(self.dbs.keys()):
            self._check_archive_bulk(bulk_archive, year, limit=0)
        logger.info('End sync {} worker: {:,} processed {:,} in archive'
            .format(self.config['resource'], rows_count, archive_count),
            extra={'MESSAGE_ID': 'end_sync_worker'})

    def _check_archive_bulk(self, bulk_archive, year, limit=100):
        if len(bulk_archive[year]) < limit:
            return
        logger.info('Check {} archive {} with {} items'
            .format(self.config['resource'][:-1], year, len(bulk_archive[year])),
            extra={'MESSAGE_ID': 'check_archive'})
        archive_db = self.dbs[year]
        view_path = '_design/{}/_view/by_dateModified'.format(
            self.config['resource'])
        bulk_values = bulk_archive[year].values()
        resp_dict = {}
        for n in range(5):
            try:
                start = time.time()
                rows = archive_db.view(view_path, keys=bulk_values)
                end = time.time() - start
                resp_dict = {k.id: k.key for k in rows}
                logger.debug('Check in {} archive {} duration: {} sec, {} found'
                    .format(self.config['resource'][:-1], year, end, len(resp_dict)),
                    extra={'CHECK_IN_ARCHIVE': end})
                break
            except Exception as e:
                logger.error('Error while bulk check (try {}) {} items '
                    'in {} archive {} error {}'.format(n + 1, len(bulk_values),
                        self.config['resource'], year, e.message),
                    extra={'MESSAGE_ID': 'exceptions'})
                if n > 3:
                    raise
                sleep(1 + 2 * n)
        # process results of view
        for doc_id, date_modified in bulk_archive[year].items():
            if doc_id in resp_dict and resp_dict[doc_id] == date_modified:
                continue
            doc = self.db.get(doc_id)
            archive_doc = self._get_archive_doc(year, doc_id)
            # double check before possible delete
            if doc and archive_doc and doc.get('dateModified') and \
                    doc['dateModified'] == archive_doc['dateModified']:
                continue
            if doc and doc.get('archived'):  # is archive stub
                # maybe we can update stub
                if archive_doc and archive_doc['dateModified'] > doc['dateModified']:
                    new_stub = self._get_archive_stub(archive_doc)
                    new_stub['_rev'] = doc['_rev']
                    logger.warning('Update {} stub {} in main (from archive {})'
                        .format(self.config['resource'][:-1], doc_id, year),
                        extra={'MESSAGE_ID': 'update_main_stub'})
                    if self.db.save(new_stub):
                        continue
                # update not possible or failed, now delete
                logger.warning('Delete {} stub {} from main (missmatch with archive {})'
                    .format(self.config['resource'][:-1], doc_id, year),
                    extra={'MESSAGE_ID': 'delete_from_main'})
                self.db.delete(doc)
            elif doc:
                logger.error('Not archived {} {} in sync with archive {}'
                    .format(doc.get('doc_type', '<doc_type>'), doc_id, year),
                    extra={'MESSAGE_ID': 'error_not_archived_doc'})
            if self.delete_from_archive and archive_doc:
                logger.warning('Delete {} {} from arhicve {} (missed stub in main)'
                    .format(self.config['resource'][:-1], doc_id, year),
                    extra={'MESSAGE_ID': 'delete_from_archive'})
                archive_db.delete(archive_doc)
            elif archive_doc:
                self.exists_in_archive[doc_id] = True
            self.add_to_retry_queue(doc_id, self.sync_archive_priority)
        # clear bulk
        bulk_archive[year] = {}

    def _is_archive_doc(self, doc):
        return not doc.get('archived') and \
            doc.get('status') in self.archive_status

    def _get_archive_year(self, doc):
        if 'archived' in doc:
            return doc['archived']
        keyid = self.config['resource'][:-1] + 'ID'
        parts = doc.get(keyid, '').split('-')
        if len(parts) < 5:
            return None
        for i in range(1, 5):
            if len(parts[i]) == 4 and parts[i][:2] == '20':
                return parts[i]

    def _get_archive_stub(self, doc, year=None):
        keyid = self.config['resource'][:-1] + 'ID'
        fields = ['_id', 'id', 'doc_type', 'status', 'dateModified', keyid]
        if not year:
            year = self._get_archive_year(doc)
        stub = {'archived': year}
        for k in fields:
            if k in doc:
                stub[k] = doc[k]
        return stub

    def _get_stub_from_view_row(self, row, year):
        keyid = self.config['resource'][:-1] + 'ID'
        doc_type = self.config['resource'][:-1].title()
        resource_id = row['value'].get(keyid, row['key'])
        date_modified = row['value'].get('dateModified', row['key'])
        doc = {
            '_id': row['id'],
            'id': row['id'],
            'doc_type': doc_type,
            'status': row['value']['status'],
            'dateModified': date_modified,
            keyid: resource_id
        }
        assert doc[keyid][:2] == 'UA'
        assert doc['dateModified'][:2] == '20'
        return self._get_archive_stub(doc, year)

    def _get_archive_doc(self, year, doc_id):
        for n in range(5):
            try:
                return self.dbs[year].get(doc_id)
            except Exception as e:
                logger.error('Error while get doc {} from {} arhicve {}: {} {} '
                    '(try {})'.format(doc_id, self.config['resource'], year,
                        type(e).__name__, e.message, n + 1))
                if n > 3:
                    raise
                sleep(1 + 2 * n)

    def _save_bulk_to_archive(self):
        bulk_archive = {}
        stub_archive = {}
        # fill archive queues
        for doc_id, doc in self.bulk.items():
            if not self._is_archive_doc(doc):
                continue
            year = self._get_archive_year(doc)
            if year not in self.dbs:
                logger.error('No archive {} for {} {}'.format(
                    year, self.config['resource'][:-1], doc_id))
                continue
            if year not in bulk_archive:
                bulk_archive[year] = {}
            archive_doc = None
            doc_rev = doc.pop('_rev', None)
            stub = self._get_archive_stub(doc, year)
            if doc_rev:
                stub['_rev'] = doc_rev
                archive_doc = self._get_archive_doc(year, doc_id)
            elif self.exists_in_archive.get(doc_id):
                self.exists_in_archive.pop(doc_id)
                archive_doc = self._get_archive_doc(year, doc_id)
            elif self.priority_cache[doc_id] > 1:
                archive_doc = self._get_archive_doc(year, doc_id)
            if archive_doc:
                doc['_rev'] = archive_doc['_rev']
                changes = archive_doc.pop('changes', [])
                patch = make_patch(doc, archive_doc)
                if patch and patch.patch:
                    changes.insert(0, patch.patch)
                doc['changes'] = changes
                logger.warning('Update archive {} {} {} rev {}'.format(
                    year, self.config['resource'][:-1], doc_id, doc['_rev']))
            bulk_archive[year][doc_id] = doc
            stub_archive[doc_id] = stub
        # flush archive queues
        for year, bulk_items in bulk_archive.items():
            logger.debug('Try flush {} archive {} with {} items'
                .format(self.config['resource'], year, len(bulk_items)))
            try:
                archive_db = self.dbs[year]
                start = time.time()
                res = archive_db.update(bulk_items.values())
                end = time.time() - start
                logger.debug('Bulk save archive {} duration: {} sec.'.format(year, end),
                             extra={'SAVE_BULK_DURATION': end})
            except Exception as e:
                logger.error('Error while saving bulk {} {} in db: {} {}'
                    .format(self.config['resource'], year, type(e).__name__, e.message),
                    extra={'MESSAGE_ID': 'exceptions'})
                continue
            for success, doc_id, rev_or_exc in res:
                if success:
                    if rev_or_exc.startswith('1-'):
                        logger.info('Save {} {} to archive {}'.format(
                            self.config['resource'][:-1], doc_id, year),
                            extra={'MESSAGE_ID': 'save_archive_documents'})
                    else:
                        logger.info('Update {} {} in archive {}'.format(
                            self.config['resource'][:-1], doc_id, year),
                            extra={'MESSAGE_ID': 'update_archive_documents'})
                    # now add stub in bulk
                    logger.debug('Add stub for {} {} archive {}'
                        .format(self.config['resource'][:-1], doc_id, year),
                        extra={'MESSAGE_ID': 'add_stub'})
                    self.bulk[doc_id] = stub_archive[doc_id]
                else:
                    if rev_or_exc.message in (u'Document update conflict.',
                                              u'New doc with oldest dateModified.'):
                        try:
                            bulk_doc = bulk_items[doc_id]
                            archive_doc = self._get_archive_doc(year, doc_id)
                            if archive_doc and archive_doc['dateModified'] == bulk_doc['dateModified']:
                                logger.info('Add stub for existing {}'.format(doc_id),
                                    extra={'MESSAGE_ID': 'add_stub_for_existing'})
                                self.bulk[doc_id] = stub_archive[doc_id]
                                continue
                        except Exception as e:
                            logger.error('Error when checking {} {} in archive {} reason '
                                '{} {} {}'.format(self.config['resource'][:-1], doc_id, year,
                                    rev_or_exc.message, type(e).__name__, e.message),
                                extra={'MESSAGE_ID': 'exception'})
                        # update exists cache
                        self.exists_in_archive[doc_id] = True
                    # remove from current bulk and add to retry queue
                    self.bulk.pop(doc_id)
                    self.add_to_retry_queue(
                        doc_id, priority=self.priority_cache[doc_id]
                    )
                    logger.error(
                        'Put to retry queue {} {} archive {} with reason: '
                        '{}'.format(self.config['resource'][:-1],
                                    doc_id, year, rev_or_exc.message))

    def _save_bulk_docs(self, flush=False):
        if (len(self.bulk) > self.bulk_save_limit or
                (datetime.now() - self.start_time).total_seconds() >
                self.bulk_save_interval or self.exit or flush):
            if self.archive:
                self._save_bulk_to_archive()
            if len(self.bulk) == 0:
                return
            try:
                logger.debug('Try save bulk: {}'.format(len(self.bulk)),
                             extra={'SAVE_BULK_LEN': len(self.bulk)})
                start = time.time()
                res = self.db.update(self.bulk.values())
                end = time.time() - start
                logger.debug('Bulk save duration: {} sec.'.format(end),
                             extra={'SAVE_BULK_DURATION': end})
                for resource_item in self.bulk.values():
                    ts = (datetime.now(TZ) -
                          parse_date(resource_item[
                              'dateModified'])).total_seconds()
                    logger.debug('{} {} timeshift is {} sec.'.format(
                        self.config['resource'][:-1], resource_item['id'], ts),
                        extra={'DOCUMENT_TIMESHIFT': ts})
                logger.info('Save bulk {} docs to db.'.format(len(self.bulk)))
            except Exception as e:
                logger.error('Error while saving bulk_docs in db: {}'.format(
                    e.message), extra={'MESSAGE_ID': 'exceptions'})
                for doc in self.bulk.values():
                    self.add_to_retry_queue(
                        doc['id'], priority=self.priority_cache[doc['id']]
                    )
                self.start_time = datetime.now()
                self.priority_cache = {}
                self.bulk = {}
                return
            for success, doc_id, rev_or_exc in res:
                if success:
                    if not rev_or_exc.startswith('1-'):
                        logger.info('Update {} {}'.format(
                            self.config['resource'][:-1], doc_id),
                            extra={'MESSAGE_ID': 'update_documents'})
                    else:
                        logger.info('Save {} {}'.format(
                            self.config['resource'][:-1], doc_id),
                            extra={'MESSAGE_ID': 'save_documents'})
                    continue
                else:
                    if rev_or_exc.message in (u'Document update conflict.',
                                              u'New doc with oldest dateModified.'):
                        try:
                            db_doc = self.db.get(doc_id)
                            bulk_doc = self.bulk[doc_id]
                            if db_doc and db_doc['dateModified'] == bulk_doc['dateModified']:
                                logger.debug('Ignored {} {} with reason: {}'.format(
                                    self.config['resource'][:-1], doc_id, rev_or_exc),
                                    extra={'MESSAGE_ID': 'skiped'})
                                continue
                        except Exception as e:
                            logger.error('Error when checking {} {} reason {} exception {}'.format(
                                self.config['resource'][:-1], doc_id, rev_or_exc.message, e),
                                extra={'MESSAGE_ID': 'exception'})
                    self.add_to_retry_queue(
                        doc_id, priority=self.priority_cache[doc_id]
                    )
                    logger.error(
                        'Put to retry queue {} {} with reason: '
                        '{}'.format(self.config['resource'][:-1],
                                    doc_id, rev_or_exc.message))
            self.bulk = {}
            self.priority_cache = {}
            self.start_time = datetime.now()

    def _run(self):
        if self.api_clients_queue is None and self.dbs:
            return self._run_sync_worker()

        while not self.exit:
            # Try get api client from clients queue
            api_client_dict = self._get_api_client_dict()
            if api_client_dict is None:
                logger.debug('API clients queue is empty.')
                sleep(self.config['worker_sleep'])
                continue

            # Try get item from resource items queue
            priority, resource_item_id = self._get_resource_item_from_queue()
            if resource_item_id is None:
                self.api_clients_queue.put(api_client_dict)
                logger.debug('PUT API CLIENT: {}'.format(api_client_dict['id']),
                             extra={'MESSAGE_ID': 'put_client'})
                logger.debug('Resource items queue is empty.')
                sleep(self.config['worker_sleep'])
                continue


            try:
                # Resource object from local db server
                local_resource_item = self.db.get(resource_item_id)
            except Exception as e:
                self.api_clients_queue.put(api_client_dict)
                logger.debug('PUT API CLIENT: {}'.format(api_client_dict['id']),
                             extra={'MESSAGE_ID': 'put_client'})
                self.add_to_retry_queue(resource_item_id, priority=priority)
                logger.error('Error while getting resource item from couchdb: '
                             '{}'.format(repr(e)),
                             extra={'MESSAGE_ID': 'exceptions'})
                continue

            # Try get resource item from public server
            public_resource_item = self._get_resource_item_from_public(
                api_client_dict, priority, resource_item_id)
            if public_resource_item is None:
                continue

            # Add docs to bulk
            self._add_to_bulk(
                local_resource_item, public_resource_item, priority
            )

            # Save/Update docs in db
            self._save_bulk_docs()

    def shutdown(self):
        self.exit = True
        logger.info('Worker complete his job.')
