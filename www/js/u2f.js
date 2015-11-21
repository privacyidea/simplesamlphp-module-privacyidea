function sign_u2f_request(challenge, keyHandle, appId) {
	console.log(challenge);
	console.log(keyHandle);
	console.log(appId);

	var signRequests = [{"challenge": challenge, 
				"keyHandle": keyHandle,
				"appId": appId,
				"version": "U2F_V2"}];
        u2f.sign(signRequests, function (result) {
		console.log(result);
		document.getElementById('signatureData').value = result.signatureData;
		document.getElementById('clientData').value = result.clientData;
		document.forms['piLoginForm'].submit();
	});
	
}
