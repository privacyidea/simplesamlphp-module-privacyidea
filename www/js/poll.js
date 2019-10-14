function poll_token_challenges(token) {
    'use strict';

    setInterval(
        function() {
            var stateId = new URLSearchParams(new URL(window.location).search).get('StateId');
            var xmlHttpRequest = new XMLHttpRequest();
            xmlHttpRequest.onreadystatechange = function() {
                if (xmlHttpRequest.readyState === XMLHttpRequest.DONE) {
                    if (xmlHttpRequest.status === 200) {
                        if (JSON.parse(xmlHttpRequest.responseText)) {
                            document.getElementById('piLoginForm').submit();
                        }
                    } else {
                        console.error("Request error: " + xmlHttpRequest.statusText);
                    }
                }
            };
            xmlHttpRequest.open('GET', "polltransaction.php?StateId=" + stateId);
            xmlHttpRequest.send();
        },
        2000
    );
}