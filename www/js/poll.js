function poll_token_challenges(token) {
    'use strict';

    setInterval(
        function() {
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
            xmlHttpRequest.open(
                'GET',
                "checktokenchallenges.php?token="
                    + token
                    + "&StateId="
                    + new URLSearchParams(new URL(window.location).search).get('StateId'));
            xmlHttpRequest.send();
        },
        2000
    );
}