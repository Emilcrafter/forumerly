
const http = require('http');


function compare(token1, token2){
    
    return new Promise((resolve, reject) => {

        let postData = JSON.stringify({token1, token2});

        const options = {
            hostname: 'localhost',
            port: 8087,
            path: '/',
            method: 'POST',
            timeout: 60000,
            headers: {
              'Content-Type': 'json/application',
              'Content-Length': Buffer.byteLength(postData)
            }
        }

        const req = http.request(options, (resp) => {
          
            let data = ''
            // A chunk of data has been recieved.
            resp.on('data', (chunk) => {
              data += chunk;
            });
          
            // The whole response has been received. Print out the result.
            resp.on('end', () => {
              
                const result = JSON.parse(data);
                resolve(result.result)
            });
          
          }).on("error", (err) => {
            console.log("Error: " + err.message);
          });
        
        req.setTimeout(60000, function() {
          // request.abort();
        });
        req.write(postData);
        req.end();
    })
}


exports.compare = compare