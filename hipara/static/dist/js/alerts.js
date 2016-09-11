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
                    perform_lr = (alerts[i].host_perform_lr) ? "checked" : ""
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
                                +"<b>Message: </b>"
                                +alerts[i].alertMessage+

                                ((alerts[i].process_name) ?
                                ("<br><b>Process Name: </b>"
                                +alerts[i].process_name ) : "")+

                                ((alerts[i].host_uuid) ?
                                ("<br><b>Host Uuid: </b>"
                                +alerts[i].host_uuid ) : "")+

                                ((alerts[i].host_ipaddr) ?
                                ("<br><b>Host IP address: </b>"
                                +alerts[i].host_ipaddr  ) : "")+

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
                                <div class='form-group'>\
									<input type='checkbox' host_id="+alerts[i].host_id+" \
									class='checkbox_perform_lr' "+ perform_lr +" >\
                                </div>\
                            </div>\
                        </div>\
                        </li>\
                    ");
                }

				// Stylize the perform LR checkboxes
                $('.checkbox_perform_lr').each(function(){
                	var sytel_class = (this.checked) ? "icheckbox_line-green": "icheckbox_line-aero"
                	var label_text =  (this.checked) ? "Live response pending on host": "Perform live response on host"
                	$(this).iCheck({
                		checkboxClass: sytel_class,
                		insert: '<div class="icheck_line-icon"></div><span class="perform_lr_label">' + label_text + "</span>"
					})
				});

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

    // Perform LR listeners
    $(document).on('ifChecked', '.checkbox_perform_lr', function(event){
    	var host_id = event.target.attributes.host_id.value
    	$.post("/api/v1/host/"+host_id+"/update_lr/", {'lr_state': true} )
    		.success(function(response){
    			$('.checkbox_perform_lr[host_id='+host_id+']').each(function(){
					$(this).prop('checked', true)
					$(this).parent().addClass('checked')
					$(this).parent().removeClass('icheckbox_line-aero')
					$(this).parent().addClass('icheckbox_line-green')
					$(this).parent().children('.perform_lr_label').text("Live response pending on host")
				});
    		})
    		.fail(function(response){
    			console.log('fail')
    			console.log(response)
    		})

    });
    $(document).on('ifUnchecked', '.checkbox_perform_lr', function(event){
    	var host_id = event.target.attributes.host_id.value
    	$.post("/api/v1/host/"+host_id+"/update_lr/", {'lr_state': false} )
    		.success(function(response){
				$('.checkbox_perform_lr[host_id='+host_id+']').each(function(){
					$(this).prop('checked', false)
					$(this).parent().removeClass('checked')
					$(this).parent().removeClass('icheckbox_line-green')
					$(this).parent().addClass('icheckbox_line-aero')
					$(this).parent().children('.perform_lr_label').text("Perform live response on host")
				});
			})
			.fail(function(response){
				console.log('fail')
				console.log(response)
			})
    });

    function init() {
        page_number = 0;
        dateCheck = '';
        $('#searchError').text('');
        $(".timeline").empty();
        getAlerts();
    }

});
