// Routes for topic and threads pages
const express = require('express')
const router = express.Router()
const mongo = require('../db')
const locations = require('../locations')
const slots = require('../park_slots.js')
const ObjectID = require('mongodb').ObjectID
const moment = require('moment-timezone')




// Middleware requiring the user to be authenticated
function loginRequired(req, res, next) {
  if (!req.isAuthenticated()) {
    req.flash('info', 'You must be logged in to perform that action.')
    return res.redirect('back')
  }
  next()
}


router

    // POST new reply to specified thread id
  .post('/park', loginRequired, (req, res) => {

    // Validate the place license
    let licensePlate = req.body.licensePlate;
    let location = req.body.location;
    let mintime = req.body.mintime;

    if(!location) {
      req.flash("error", "You must provide a valid location")
      res.redirect('/')
      return
    }
    let self = this;
    if(location) {
      locations.getLocationById(location, (e) => {

        if(e.length != 1) {
          location  = null
          req.flash("error", "Location does not exist")
          res.redirect('/')
          return
        }
        if(!licensePlate) {
          req.flash("error", "You must provide the license plate")
          res.redirect('/')
          return
        }

      if(licensePlate.length != 6) {
        req.flash("error", "You must provide a valid, 6 characters, License plate " + licensePlate + " " + licensePlate.length)
        res.redirect('/')
        return
      }

      let loc = e[0];
      slots.getParkedByLicensePlateAndLocation(licensePlate, loc, (e) => {
        console.log(e);
        if(e.length != 0 ) {
          // This car is already parked here, send error
          req.flash("error", "This car is already parked in the selected location. Do not waste your money !")
          // TODO check if it comes not from the browser and then use as an API
          res.redirect('/')
        } else {
          // Here insert the parking or return an error if the car plate is already parked here.
          // Check if the amount of time is greater than zero
          if(mintime <= 0) {
            req.flash("error", "Please provide the minimum time you will park. It should be greater than zero.")
            res.redirect('/')
          } else {
            slots.addPark(loc, req.user, licensePlate, mintime, (r) => {
              console.log(r)
              res.redirect('/')
            })
          }


        }

      })

    }
  )}
})
// /createReply/:id
.get('/up', loginRequired, (req, res) => {
    console.log("Unparking")
    let slot = slots.getParkedbyId(req.user, req.query.id, (e) => {
      // Check that this user was the one parking it...otherwise error
      console.log(e)
      if(e.length != 1) {
        req.flash('error', "Invalid unparking, this user did not park the car to begin with")
        res.redirect('/')
      }
      else {
        // Remove the park
        slots.deleteParked(e[0], (r) => {
          if(r) {
            req.flash("info", e[0].licensePlate +  " successfully unparked")
          }
        });
        res.redirect('/')
      }

    })
  })

// Export these routes to be used in app.js
module.exports = router
