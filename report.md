# ReDoS
    
```javascript
fetch('/upload', { 
    method: 'POST', 
    headers: { 
        ['content-type']: 'multipart/form-data;
         boundary=----WebKitFormBoundaryoo6vortfDzBsDiro', ['content-length']: '145', host: '127.0.0.1:3000', connection: 'keep-alive', }, body: '------WebKitFormBoundaryoo6vortfDzBsDiro\r\n Content-Disposition: form-data; name="bildbeschreibung"\r\n\r\n\r\n------WebKitFormBoundaryoo6vortfDzBsDiro--' });
```
This request crashes the web server due to [CVE-2022-24434](https://www.cve.org/CVERecord?id=CVE-2022-24434)

We can mitigate this bug by 
1. Using a different parser
2. Handling the error thrown by the parser

in `routes/user.js`, change this:
```javascript
const multer = require('multer')
const upload = multer({dest: 'public/images/profileImages', limits: {fileSize: 2000000}})
const uploadUsers = multer({storage: multer.memoryStorage(), limits: {fileSize: 2000000}})
```
to this:
```javascript
const multer = require('multer')
const upload = multer({dest: 'public/images/profileImages', limits: {fileSize: 2000000}}) 
const uploadUsers = multer({storage: multer.memoryStorage(), limits: {fileSize: 2000000}})

const uploadSingle = x => {
    try {
        return upload.single(x)
    } catch (error) {
        console.log(error)
    }
}

const uploadUsersSingle = x => {
    try {
        return uploadUsers.single(x)
    } catch (error) {
        console.log(error)
    }
}
```

and use the functions `updateSingle` and `uploadUsersSingle` instead of `upload.single` and `uploadUsers.single` in `/upload` and `/upload/users` respectively. This is a temporary fix, which mitigates the ReDoS vulnerability. The real fix would be to use a different parser, which does not have this vulnerability.

With this fix implemented, the server does not crash anymore. It instead returns a 500 error, which is not ideal, but better than crashing the server.