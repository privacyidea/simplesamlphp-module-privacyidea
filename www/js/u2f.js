function sign_u2f_request(signRequests) {

	var appId = signRequests[0]["appId"];
	var challenge = signRequests[0]["challenge"];
	var registeredKeys = [];

	registeredKeys.push({
		version: "U2F_V2",
		keyHandle: signRequests[0]["keyHandle"]
	});

	u2f.sign(appId, challenge, registeredKeys, function (result) {
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
	var registeredKeys = [];
	registeredKeys.push({
		version: "U2F_V2",
		keyHandle: keyHandle
	});
	u2f.register(appId, registerRequests, registeredKeys, function (result) {
		console.log(result);
		document.getElementById("clientData").value = result.clientData;
		document.getElementById("registrationData").value = result.registrationData;
		document.forms["piLoginForm"].submit();
	})
}
