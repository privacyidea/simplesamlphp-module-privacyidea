function sign_u2f_request(signRequests) {
	u2f.sign(signRequests, function (result) {
		console.log(result);
		if (result.errorMessage === "InvalidStateError: A request is already pending.") {
			document.getElementById("u2fTryAgain").style.display = "block";
		} else {
			document.getElementById("signatureData").value = result.signatureData;
			document.getElementById("clientData").value = result.clientData;
			document.forms["piLoginForm"].submit();
		}
	})
}

function register_u2f_request(appId, challenge, keyHandle) {
	var registerRequests = [{
		"challenge": challenge,
		"appId": appId,
		"version":"U2F_V2"
	}];
	var signRequests = [{
		"challenge": challenge,
		"keyHandle": keyHandle,
		"appId": appId,
		"version": "U2F_V2"
	}];
	u2f.register(registerRequests, signRequests, function (result) {
		console.log(result);
		document.getElementById("clientData").value = result.clientData;
		document.getElementById("registrationData").value = result.registrationData;
		document.forms["piLoginForm"].submit();
	})
}
