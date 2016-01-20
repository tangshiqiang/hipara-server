$(docuemnt).ready(function(){

if (!library)
   var library = {};

library.json = {
   replacer: function(match, pIndent, pKey, pVal, pEnd) {
      var key = '<span class=json-key>';
      var val = '<span class=json-value>';
      var str = '<span class=json-string>';
      var r = pIndent || '';
      if (pKey)
         r = r + key + pKey.replace(/[": ]/g, '') + '</span>: ';
      if (pVal)
         r = r + (pVal[0] == '"' ? str : val) + pVal + '</span>';
      return r + (pEnd || '');
      },
   prettyPrint: function(obj) {
      var jsonLine = /^( *)("[\w]+": )?("[^"]*"|[\w.+-]*)?([,[{])?$/mg;
      return JSON.stringify(obj, null, 3)
         .replace(/&/g, '&amp;').replace(/\\"/g, '&quot;')
         .replace(/</g, '&lt;').replace(/>/g, '&gt;')
         .replace(jsonLine, library.json.replacer);
      }
   };

var account = {"value":[{"file_category_id":"21","name":"cksdh"},{"file_category_id":"30","name":"dksjhdgsa"},{"file_category_id"
:"32","name":"dlskajdadksa"},{"file_category_id":"13","name":"fkdjfs"},{"file_category_id":"11","name"
:"fkfnkjfsd"},{"file_category_id":"19","name":"fkhsfbds fkdjs"},{"file_category_id":"15","name":"fkldjskfdsn fkdsfdhs"},{"file_category_id":"14","name":"flidskufhds"},{"file_category_id":"16","name":"gkljhf dfdksjfdhs"
},{"file_category_id":"17","name":"glkuhf flkdsiuf"},{"file_category_id":"27","name":"kdlsjfhsb"},{"file_category_id"
:"24","name":"kdsnjdbsajdsa"},{"file_category_id":"18","name":"kfjo fkesie"},{"file_category_id":"33"
,"name":"klsajdhgsadjsa"},{"file_category_id":"26","name":"kmdjshg"},{"file_category_id":"8","name":"kmkd dksjd"},{"file_category_id":"20","name":"kskajd"},{"file_category_id":"23","name":"ldiusyd"},{"file_category_id"
:"31","name":"ldksaiudsjakdsa"},{"file_category_id":"22","name":"ldsh"},{"file_category_id":"10","name"
:"lfkdjb"},{"file_category_id":"7","name":"lfkhgfds"},{"file_category_id":"12","name":"liufjdsk"},{"file_category_id"
:"29","name":"lkdjsdhgs"},{"file_category_id":"25","name":"lkdjss"},{"file_category_id":"9","name":"pratibha"
},{"file_category_id":"28","name":"skjdhsajdsa"}],"number_of_pages":1};

$('.json').html(library.json.prettyPrint(account));
