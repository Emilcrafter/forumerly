const mongo = require('./db')
const ObjectID = require('mongodb').ObjectID
const moment = require('moment-timezone')



function getLocations(cb){

  // REduce on the system types
  mongo.db.collection("locations").find({}).toArray((err, r) => {
    console.log(err);
      cb(r);
  })
}

function getLocationById(id, cb) {
  mongo.db.collection("locations").find({'_id': ObjectID(id)}).toArray((err, r) => {
    if(err) console.log(err)

    cb(r)
  })
}

module.exports = {
  getLocations,
  getLocationById
}
