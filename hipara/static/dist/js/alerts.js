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
                            <div class='timeline-footer'>\
                                <div class='form-group'>\
                                    <label>Evaluate:</label> \
                                    <select class='form-control alert-eval' alert_id='" +alerts[i].alert_id+"'>\
                                        <option value='0' " +((alerts[i].alertEval == 0) ? "selected" : "")+">None</option>\
                                        <option value='1' " +((alerts[i].alertEval == 1) ? "selected" : "")+">True Positive</option>\
                                        <option value='2' " +((alerts[i].alertEval == 2) ? "selected" : "")+">False Positive</option>\
                                    </select>\
                                </div>\
                            </div>\
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

    
    // AJAX CSRF
    $.ajaxSetup({ 
         beforeSend: function(xhr, settings) {
             function getCookie(name) {
                 var cookieValue = null;
                 if (document.cookie && document.cookie != '') {
                     var cookies = document.cookie.split(';');
                     for (var i = 0; i < cookies.length; i++) {
                         var cookie = jQuery.trim(cookies[i]);
                         // Does this cookie string begin with the name we want?
                         if (cookie.substring(0, name.length + 1) == (name + '=')) {
                             cookieValue = decodeURIComponent(cookie.substring(name.length + 1));
                             break;
                         }
                     }
                 }
                 return cookieValue;
             }
             if (!(/^http:.*/.test(settings.url) || /^https:.*/.test(settings.url))) {
                 // Only send the token to relative URLs i.e. locally.
                 xhr.setRequestHeader("X-CSRFToken", getCookie('csrftoken'));
             }
         } 
    });
        
    // Post on alert eval change
    $(document).on('change', '.alert-eval', function(event){
        var alert_id = $(this).attr('alert_id');
        var alert_eval = this.value;
        $.post("/api/v1/alert/"+alert_id+"/update_eval/"+alert_eval+"/")
            .success(function(response){
                console.log(response);
            })
            .fail(function(response){
                console.log(response);
            });
    });
    
    function init() {
        page_number = 0;
        dateCheck = '';
        $('#searchError').text('');
        $(".timeline").empty();
        getAlerts();
    }

});
