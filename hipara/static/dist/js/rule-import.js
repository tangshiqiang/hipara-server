$('#rule-upload').validator().on('submit', function(e) {
    if (e.isDefaultPrevented()) {
        // handle the invalid form...
        $('#rule-upload-error b').text('All fields mandatory.');
        $('#import-error b').text('');
        return false;
    } else {
        // everything looks good!
        e.isDefaultPrevented();
        var formdata = $('#rule-upload').serializeArray();
        if (formdata[1].value == "0") {
            $('#rule-upload-error b').text('All fields mandatory.');
            return false;
        } else {
            e.isDefaultPrevented();
            $('#rule-upload-error b').text('');
            $('#rule-upload').validator('destroy');
        }
    }
});

$('input').on("focus", function() {
    $('#import-error b').text('');
    $('#rule-upload-error b').text('');
});
