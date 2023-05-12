const mongo = require('./db')
const ObjectID = require('mongodb').ObjectID
const moment = require('moment-timezone')


// Formats all the dates inside of a single object (the object being a single thread)
function registerVisit(useragent) {

  mongo.db.collection('clients')
  .insertOne({
    os: useragent.getOS()
  },(err, result) => {
    if (err) {return done(err)}
    console.log('The client OS: ', useragent.getOS(), ' is registered')
  })
}

function getStats(cb){
  
  const groups = {

  }
  // REduce on the system types
  mongo.db.collection("clients").find().forEach(i => {
    //console.log(i.os)
    if(!groups[i.os.name])
      groups[i.os.name] = 0;
    groups[i.os.name] += 1;
  }).then(r => {
    let cbdata = []
    for(let k in groups) {
      cbdata.push({ _id: k, value: groups[k] })
    }
    cb(cbdata)
  })
  /*
  mongo.db.collection("clients").mapReduce(function(){
    emit(this.os.name, 1)
  }, function(key, values) {return Array.sum(values)}, {
    query: {},
    out: "clients_by_os"
  }, (err, res) => {
    if(res){
      //cb([])
      let a = res.find({}).toArray();
      console.log(a)
      cb(a)

      //res.find({}, (err, docs) => {
      //  console.log(docs)
      //  docs.toArray().then(r => cb(r))
      //} )
    }
  })*/
}

module.exports = {
  registerVisit,
  getStats
}