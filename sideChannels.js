

async function findCar(registration){

    // locations are <select><option id={location}>

    const locations = [...document.querySelectorAll('option')].map(option => option.id);

    for(let i = 0; i < locations.length; i++){
        const location = locations[i];
        const data = new FormData();
        data.append('licensePlate', registration);
        data.append('location', location);
        data.append('mintime', 0);
        const response = await fetch('/park', {
            method: 'POST',
            keepalive: false,
            body: new URLSearchParams(data)
        });
        const fullText = await response.text();
        if(!fullText.includes('This car is already parked')){
            continue;
        }
        // We want to find the element with an id of the location
        const locationName = document.getElementById(location).innerText;
        console.log("Found car at location: " + locationName);
    }
}

findCar("AAAAAA");