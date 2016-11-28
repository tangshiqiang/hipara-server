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
					action = "<button class='btn btn-xs download_flow' flow_id='"+ v.flow_id +"'>"+
					"<i class='fa fa-floppy-o' aria-hidden='true'></i></button>"
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

    // Download Alert File
//	$(document).on('click', '.alert_file_download', function(event){
//		var flow_id = event.target.attributes.flow_id.value
//		var client_id = event.target.attributes.client_id.value
//		window.location.href = 'download/alert/file/' + client_id + '/' + flow_id + '/'
//
//	})

})