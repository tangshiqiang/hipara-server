$(function() {
    $('#email-tags').val('');
    var emailList = [];

    function onAddTag(tag) {
        if (isValidEmailAddress(tag)) {
            emailList.splice(1, 0, tag);
            $('#send-invite-error b').text('');
        } else {
            emailList.splice(1, 0, tag);
            remove(tag);
        }
    }

    function remove(tag) {
        var index = emailList.indexOf(tag);
        emailList.splice(1, 0, tag);
        emailList.splice(index, 1);
        $('#email-tags').removeTag(tag);
    }

    function onRemoveTag(tag) {
        var index = emailList.indexOf(tag);
        emailList.splice(index, 1);
    }

    function isValidEmailAddress(emailAddress) {
        var emailPattern =
            /^([a-z\d!#$%&'*+\-\/=?^_`{|}~\u00A0-\uD7FF\uF900-\uFDCF\uFDF0-\uFFEF]+(\.[a-z\d!#$%&'*+\-\/=?^_`{|}~\u00A0-\uD7FF\uF900-\uFDCF\uFDF0-\uFFEF]+)*|"((([ \t]*\r\n)?[ \t]+)?([\x01-\x08\x0b\x0c\x0e-\x1f\x7f\x21\x23-\x5b\x5d-\x7e\u00A0-\uD7FF\uF900-\uFDCF\uFDF0-\uFFEF]|\\[\x01-\x09\x0b\x0c\x0d-\x7f\u00A0-\uD7FF\uF900-\uFDCF\uFDF0-\uFFEF]))*(([ \t]*\r\n)?[ \t]+)?")@(([a-z\d\u00A0-\uD7FF\uF900-\uFDCF\uFDF0-\uFFEF]|[a-z\d\u00A0-\uD7FF\uF900-\uFDCF\uFDF0-\uFFEF][a-z\d\-._~\u00A0-\uD7FF\uF900-\uFDCF\uFDF0-\uFFEF]*[a-z\d\u00A0-\uD7FF\uF900-\uFDCF\uFDF0-\uFFEF])\.)+([a-z\u00A0-\uD7FF\uF900-\uFDCF\uFDF0-\uFFEF]|[a-z\u00A0-\uD7FF\uF900-\uFDCF\uFDF0-\uFFEF][a-z\d\-._~\u00A0-\uD7FF\uF900-\uFDCF\uFDF0-\uFFEF]*[a-z\u00A0-\uD7FF\uF900-\uFDCF\uFDF0-\uFFEF])\.?$/i;
        return emailPattern.test(emailAddress);
    };

    $('#email-tags').tagsInput({
        'height': '100px',
        'width': '300px',
        'interactive': true,
        'defaultText': 'Add emails',
        'onAddTag': onAddTag,
        'onRemoveTag': onRemoveTag,
        'removeWithBackspace': true,
        'placeholderColor': '#666666'
    });

    $('#send-invite').validator().on('submit', function(e) {
        var formdata = $('#send-invite').serializeArray();
        // everything looks good!
        $("#email-error b").text('');
        if ($("#email-tags").val() == "") {
            $('#send-invite-error b').text('Provide valid emails.');
            return false;
        } else {
            $('#send-invite-error b').text('');
            $('#email-tags').val(emailList.toString());
        }
    });

});
