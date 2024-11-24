function(doc) {
    if(doc.doc_type == 'Tender' && doc.status != 'draft') {
        var fields=['archive_stub', 'auctionPeriod', 'status', 'tenderID', 'procurementMethodType', 'next_check'], data={};
        for (var i in fields) {
            if (doc[fields[i]]) {
                data[fields[i]] = doc[fields[i]]
            }
        }
        emit(doc.dateModified, data);
    }
}
