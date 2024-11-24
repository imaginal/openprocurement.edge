function(doc) {
    if(doc.doc_type == 'Tender') {
        var fields=['archive_stub', 'dateModified', 'status'], data={};
        for (var i in fields) {
            if (doc[fields[i]]) {
                data[fields[i]] = doc[fields[i]]
            }
        }
        emit(doc.tenderID, data);
    }
}