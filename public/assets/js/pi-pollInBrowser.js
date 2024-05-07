window.onload = () =>
{
    function pollInBrowser()
    {
        piDisableElement("pushButton");
        let worker;
        if (typeof (Worker) !== "undefined")
        {
            if (typeof (worker) == "undefined")
            {
                worker = new Worker('../../../js/pi-pollTransaction.worker.js');
                document.getElementById("pi-form-submit-button").addEventListener('click', function (e)
                {
                    worker.terminate();
                    worker = undefined;
                });
                worker.postMessage({'cmd': 'url', 'msg': piGetValue("pollInBrowserUrl")});
                worker.postMessage({'cmd': 'transactionID', 'msg': piGetValue("transactionID")});
                worker.postMessage({'cmd': 'start'});
                worker.addEventListener('message', function (e)
                {
                    let data = e.data;
                    switch (data.status)
                    {
                        case 'success':
                            piSubmit();
                            break;
                        case 'error':
                            let errorMessage = "Poll in browser error: " + data.message;
                            console.log(errorMessage);
                            piSetValue("errorMessage", errorMessage);
                            piSetValue("pollInBrowserFailed", true);
                            piEnableElement("pushButton");
                            worker = undefined;
                    }
                });
            }
        }
        else
        {
            console.log("Sorry! No Web Worker support.");
            worker.terminate();
            piSetValue("errorMessage", "Poll in browser error: No Web Worker support.");
            piSetValue("pollInBrowserFailed", true);
            piEnableElement("pushButton");
        }
    }

    if (piGetValue("mode") === "push" && piGetValue("pollInBrowser") === true && piGetValue("pollInBrowserFailed") !== true)
    {
        pollInBrowser();
    }
}