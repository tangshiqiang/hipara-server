$(function() {
    var page_number = 0;
    var page_size = 10;
    var dateCheck = '';

    $("#alerts-form").validator().on('submit', function(e) {
        if (e.isDefaultPrevented()) {
            // handle the invalid form...
            e.preventDefault();
        } else {
            // everything looks good!
            e.preventDefault();
            init();
        }
    });


    $("#alerts-form")[0].reset();

    $('#clearResult').click(function(){
        $("#alerts-form")[0].reset();
        init();
    })

    init();
    function getAlerts() {
        var searchData = $('#alerts-form').serialize();
        page_number +=1;

        $.ajax({
            url: "/api/v1/alerts?page_size="+page_size+"&page_number=" + page_number + "&" + searchData,
            type: "GET"
        }).done(function(response, textStatus, jqXHR) {

            if(jqXHR.status == 200){
                var createdAt = '';
                var alerts = response.alerts;
                for (var i = 0, len = alerts.length; i < len; i++) {
                    createdAt = alerts[i].timeStamp.substring(0, 12);
                    if( createdAt !== dateCheck ){
                        $(".timeline").append("\
                        <li class='time-label'>\
                        <span class='bg-red'>"
                            +createdAt+
                        "</span>\
                        </li>");
                        dateCheck = createdAt;
                    }

                    $(".timeline").append("\
                        <li><i class='fa fa-bell'></i>\
                        <div class='timeline-item' >\
                        <span class='time'><i class='fa fa-clock-o'></i>&nbsp;&nbsp;"
                         +alerts[i].timeStamp.substring(12)+
                        "</span>\
                            <h3 class='timeline-header'><b>"
                            +alerts[i].hostName+
                            "&nbsp;&nbsp;&nbsp;:&nbsp;&nbsp;&nbsp;"
                            +alerts[i].fileName+
                            "</b></h3>\
                            <div class='timeline-body'>"
                                +alerts[i].alertMessage+
                            "</div>\
                        </div>\
                        </li>\
                    ");
                }
                $('#searchError').text();
                if(alerts.length == page_size ){
                    $('#showMore').show();
                }else {
                    $('#searchError').text('No more data found.'); error();
                }
        }else if(jqXHR.status == 204){
            if( page_number > 1){
                $('#searchError').text('No more data found.');
            }
            else {
                $('#searchError').text('No data found.');
            }
            error();
        }
        }).fail(function(jqXHR, textStatus, errorThrown) {
        });
    }

    function error(){
        $('#showMore').hide();
    }

    $('#showMore').click(function(){
        getAlerts();
    });

    function init() {
        page_number = 0;
        dateCheck = '';
        $('#searchError').text('');
        $(".timeline").empty();
        getAlerts();
    }

});
