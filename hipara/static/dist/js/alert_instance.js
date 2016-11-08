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

})