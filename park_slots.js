const mongo = require('./db')
const ObjectID = require('mongodb').ObjectID
const moment = require('moment-timezone')
const locations = require("./locations")


function removeParked(parkid, cb) {

}

function addPark(location, user, licensePlate, mintime, cb) {
    // Validate here as well before inserting
    mongo.db.collection("slots").insertOne({
      location: location,
      user: user,
      mintime: 0,
      date: new Date(),
      licensePlate: licensePlate
    }).then((e) => {
      cb(e)
    });
}

function getParkedbyId(user, id, cb){
  mongo.db.collection("slots").find({user: user, _id: ObjectID(id)}).toArray((err, r) => {
    if(err)console.log(err);
      cb(r);
  })

}

function getParkedByLicensePlateAndLocation(plate, location, cb) {
  mongo.db.collection("slots").find({licensePlate: plate, location: location}).toArray((err, r) => {
    if(err)console.log(err);
      cb(r);
  })

}

function deleteParked(park, cb) {
  mongo.db.collection("slots").deleteOne({ _id: park._id}).then(e => {
    cb(e)
  })

}

function getParked(user, cb){

  if(user) {
    mongo.db.collection("slots").find({user: user}).toArray((err, r) => {
      r.forEach(i => {
        i.relativeDate = moment(i.date).startOf('minute').fromNow()

    });
      if(err)console.log(err);
        cb(r);
    })
  }
  else {
    cb([])
  }
}


module.exports = {
  getParked,
  addPark,
  removeParked,
  getParkedbyId,
  deleteParked,
  getParkedByLicensePlateAndLocation
}
