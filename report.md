# ReDoS
    
```javascript
fetch('/upload', { 
    method: 'POST', 
    headers: { 
        ['content-type']: 'multipart/form-data;boundary=----WebKitFormBoundaryoo6vortfDzBsDiro', ['content-length']: '145', host: '127.0.0.1:3000', connection: 'keep-alive', }, body: '------WebKitFormBoundaryoo6vortfDzBsDiro\r\n Content-Disposition: form-data; name="bildbeschreibung"\r\n\r\n\r\n------WebKitFormBoundaryoo6vortfDzBsDiro--' });
```
This request crashes the web server due to [CVE-2022-24434](https://www.cve.org/CVERecord?id=CVE-2022-24434)

We can mitigate this bug by using a different parser.

With this fix implemented, the server does not crash anymore. It instead returns a 500 error, which is not ideal, but better than crashing the server.


```javascript
async function re(iterations){
    for(let i = 0; i < iterations; i++){
        console.time("")
    }


}

```



# XSS

The website uses a CSP (Content Security Policy) which allows the browser to load scripts only from certain sources. 
In theory, this can help prevent XSS attacks. However, even though the CSP is configured in a way that makes it impossible to load scripts from external sources, or even inline in the html, we can still execute code.
By uploading a javascript file as our profile picture, we can create a resource on the website that can be loaded by the browser.

In order to actually run the code then, we need to create a script tag that loads our script from the server. This can be done by creating a post with the following content:

```html
<scr<scriptipt src="http://localhost:3000/images/profileImages/username"></script>
```


# Found a random crash

The server crashes if you send a POST request to the /createThread endpoint that does not have a ?topic query parameter.

# CSRF

The website does not have any CSRF protection for its forms. We can easily create a thread on a user's behalf by having them press a button on a website we control.

```html