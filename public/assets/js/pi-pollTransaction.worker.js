let url;
let params;
self.addEventListener('message', function (e)
{
    let data = e.data;

    switch (data.cmd)
    {
        case 'url':
            url = data.msg + "/validate/polltransaction";
            break;
        case 'transactionID':
            params = "transaction_id=" + data.msg;
            break;
        case 'start':
            if (url.length > 0 && params.length > 0)
            {
                console.log("preparing poll transaction in browser");
                pollTransactionInBrowser();
                setInterval("pollTransactionInBrowser()", 300);
            }
            break;
    }
})

function pollTransactionInBrowser()
{
    console.log("starting poll transaction in browser");
    const request = new XMLHttpRequest();

    request.open("GET", url + "?" + params, false);
console.log("open" + request.status);
    request.onload = (e) =>
    {
        console.log("onload" + request.status);

        console.log("3");

        try
        {
            if (request.readyState === 4)
            {
                if (request.status === 200)
                {
                    const response = JSON.parse(request.response);
                    if (response['result']['value'] === true)
                    {
                        self.postMessage({
                            'message': 'Polling in browser: Push message confirmed!',
                            'status': 'success'
                        });
                        self.close();
                    }
                }
                else
                {
                    console.log("err" + request.status);

                    self.postMessage({'message': request.statusText, 'status': 'error'});
                    self.close();
                }
            }
        }
        catch (e)
        {
            self.postMessage({'message': e, 'status': 'error'});
            self.close();
        }
    };

    request.onerror = (e) =>
    {
        console.log("on error" + request.status);
        self.postMessage({'message': request.statusText, 'status': 'error'});
        self.close();
    };

    request.send();
}