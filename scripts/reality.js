(function(){
  'use strict';

  function submitHandler(){
    try{
      var pass = document.getElementById('passcode').value || '';

      var form = document.createElement('form');
      form.method = 'POST';
      form.action = '/.netlify/functions/check-pass';
      // open the function response in the same tab to avoid popup blockers; change to '_blank' if you prefer new tab
      form.target = '_self';

      var input = document.createElement('input');
      input.type = 'hidden';
      input.name = 'pass';
      input.value = pass;
      form.appendChild(input);

      document.body.appendChild(form);
      form.submit();
      form.remove();
    }catch(e){
      // avoid leaking secrets - only show a generic message
      console.error('submitHandler error', e);
      alert('There was an error submitting the passcode. Open the console for details.');
    }
  }

  function attach(){
    var btn = document.getElementById('submitBtn');
    if(btn) btn.addEventListener('click', submitHandler, false);
  }

  if(document.readyState === 'loading'){
    document.addEventListener('DOMContentLoaded', attach);
  } else {
    attach();
  }

  // expose for temporary debugging if needed
  window._reality_submitHandler = submitHandler;
})();
