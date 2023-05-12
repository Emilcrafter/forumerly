// MongoDB configuration
const MongoClient = require('mongodb').MongoClient
const options = require('./options')

MongoClient.connect(options.mongoDB, (err, connection) => {
  if (err) {console.warn('error from db.js'); console.log(err)}
  else {
    module.exports.db = connection.db("forumerly") // So db is availbe everywhere by requiring this file
    console.log('Connected to mongodb successfully.')
  }
})
