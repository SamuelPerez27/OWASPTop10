(function($) {

	"use strict";


})(jQuery);

document.querySelector('form-register').addEventListener('submit', function (event) {
	event.preventDefault();
  
	var password = document.querySelector('#password').value;
	var repeatPassword = document.querySelector('#repeat-password').value;
	var errorMessage = document.querySelector('#error-message');
  
	if (password !== repeatPassword) {
	  errorMessage.style.display = 'block';
	} else {
	  errorMessage.style.display = 'none';
	  document.querySelector('form-register').submit();
	  // Enviar formulario a servidor
	}
  });

  function hacerPeticion() {
	const url = 'https://www.ejemplo.com/api/datos';
	const request = new XMLHttpRequest();
  
	request.open('GET', url);
	request.onload = function() {
	  if (request.status >= 200 && request.status < 400) {
		// La solicitud fue exitosa
		const datos = JSON.parse(request.responseText);
		console.log(datos);
	  } else {
		// Hubo un error en la solicitud
		console.log('Hubo un error al realizar la solicitud');
	  }
	};
	request.onerror = function() {
	  // Hubo un error de red al realizar la solicitud
	  console.log('Hubo un error de red al realizar la solicitud');
	};
	request.send();
  }
  
  //hacerPeticion();