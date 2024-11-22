function(doc) {
    if(doc.doc_type == 'Tender') {
        var fields=['archived', 'dateModified', 'status'], data={};
        for (var i in fields) {
            if (doc[fields[i]]) {
                data[fields[i]] = doc[fields[i]]
            }
        }
        emit(doc.tenderID, data);
    }
}