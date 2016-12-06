$(function() {

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

    // GRR modal
    $(document).on('click', '.view_grr_results', function(event){
    	$('#grrModal').modal('show');
    	$('#grrModal .modal-body').text("Loading....")

		var lr_id = event.target.attributes.lr_id.value;
		$.ajax({
			url: "/api/v1/lr/"+ lr_id +"/",
			type: "GET"
		}).success(function(response, textStatus, jqXHR){
			$('#grrModal .modal-body').text("")

			var flows = response.flows
			var flow_rows = ""
			$.each(flows, function(k,v){
				var message = "", action = ""
				if (v.state_messages) {message=state_messages}
				if (v.state == "Complete") {
					action = "<a data-toggle='modal' href='#lrfModal' class='btn btn-xs view_lrf_result'" +
					"flow_id='"+ v.flow_id +"' client_id='"+ v.client_id +"' >" +
					"<i class='fa fa-search-plus'></i></a>"
				}
				flow_rows += "<tr><td>"+
					v.flow_id+"</td><td>"+
					v.type+"</td><td>"+
					v.state+"</td><td>"+
					message+"</td><td>"+
					action+"</td>"
			})

			$('#grrModal .modal-body').append(
				"<table class='table table-striped'>" +
					"<thead>" +
						"<tr>" +
						"<th>Flow ID</th>" +
						"<th>Flow Type</th>" +
						"<th>State</th>" +
						"<th>Messages</th>" +
						"<th>Actions</th>" +
						"</tr>"+
					"</thead>" +
					"<tbody>" + flow_rows +
					"</tbody>" +
				"</table>"
			);


		}).fail(function(response, textStatus, jqXHR){

		})
    })

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

    $(document).on('click', '.view_lrf_result', function(event, something){
    	$('#lrfModal .modal-body').text("")
    	$('#lrfModal .modal-body').text("Loading....")

    	var client_id = $(this).attr('client_id')
    	var flow_id = $(this).attr('flow_id')

    	function recursive_table(item){
    		html = "<table class='table'>"
    		$.each(item, function(k,v){
				html+="<tr><td>"
				html+= k + "</td>"
				if (typeof(v.value) == 'object'){
					html += "<td>" + recursive_table(v.value) + "</td>"
				} else {
					html += "<td>" + v.value + "</td>"
				}
				html+="</tr>"
    		})
    		html += "</table>"
    		return html
    	}

    	$.get("/api/v1/client/" + client_id + "/flow/" + flow_id + "/result/",
    		function(result){
    			$('#lrfModal .modal-body').html(recursive_table(result.items))
    		}
    	)
    })

	function reload_lr_history_table(){

	}

    $(document).on('click', '.cancel_lr', function(event){
		var host_id = $(this).attr('host_id')
		var lr_id = $(this).attr('lr_id')
		$.post("/api/v1/lr/"+lr_id+"/cancel_lr/")
			.success(function(response){
				$('#host_lr_history').text("")
				$.get("/api/v1/host/"+ host_id +"/get_host_lrs/", function(result){
					html = ""
					$.each(result, function(k,v){
						console.log(v)
						html += "<tr><td>" + v.start_date + "</td><td>"
						if (v.complete){
							html +='<div class="label-success">'
							html +='<span class="label-label">'
							html +='<i class="glyphicon glyphicon-ok"></i></span>Complete</div>'

						} else {
							html += '<div class="label-warning">'
							html += '<span class="label-label">'
							html += '<i class="fa fa-clock-o"></i></span>Running..</div>'
						}
						html += '</td><td>'
						html += '<a href="#"  class="view_grr_results">'
						html += '<i lr_id="'+ v.lr_id + '" class="fa fa-search-plus" aria-hidden="true"></i></a>'
						if (v.complete == false){
							html += '<button type="button" host_id="' + host_id + '" lr_id="' + lr_id + '"'
							html += 'class="btn btn-xs btn-labeled btn-danger cancel_lr">'
							html += '<span class="btn-label"><i class="glyphicon glyphicon-remove"></i>'
							html += '</span>Cancel</button>'
						}
						html += "</td></tr>"
					})
					$('#host_lr_history').html(html)

					$('.checkbox_perform_lr[host_id='+host_id+']').each(function(){
						$(this).prop('checked', false)
						$(this).parent().removeClass('checked')
						$(this).parent().removeClass('icheckbox_line-green')
						$(this).parent().addClass('icheckbox_line-aero')
						$(this).parent().children('.perform_lr_label').text("Perform live response on host")
					});

				})
			})
			.fail(function(response){
				console.log('fail')
				console.log(response)
			})




    })

})