'use strict';

const express = require('express');
const router = express.Router();
const User = require('../models/user');
const bcrypt = require('bcrypt');
const saltRounds = 10;

router.get('/signup', (req, res, next) => {
  const formData = req.flash('signup-form-data');
  const formErrors = req.flash('signup-form-error');
  const data = {
    message: formErrors[0],
    fields: formData[0]
  };
  res.render('signup', data);
});

router.post('/signup', (req, res, next) => {
  // console.log(req.body);
  const { username, password } = req.body;

  if (!username || !password) {
    req.flash('signup-form-error', 'username and password required');
    req.flash('signup-form-data', { username });
    return res.redirect('/auth/signup');
  }

  // validate unique username
  User.findOne({ username })
    .then(result => {
      if (result) {
        req.flash('signup-form-error', 'already taken, chose another one, loser');
        req.flash('signup-form-data', { username });
        return res.redirect('/auth/signup');
      }
      const salt = bcrypt.genSaltSync(saltRounds);
      const hashedPassword = bcrypt.hashSync(password, salt);

      const user = new User({ username, password: hashedPassword });
      return user.save()
        .then(() => {
          req.session.currentUser = user;
          res.redirect('/');
        });
    });
});

router.get('/login', (req, res, next) => {
  const formData = req.flash('login-form-data');
  const formErrors = req.flash('login-form-error');
  const data = {
    message: formErrors[0],
    fields: formData[0]
  };
  res.render('login', data);
});

router.post('/login', (req, res, next) => {
  const { username, password } = req.body;

  if (!username || !password) {
    req.flash('login-form-error', 'username and password required');
    req.flash('login-form-data', { username });
    return res.redirect('/auth/login');
  }

  // validate unique username
  User.findOne({ username })
    .then(result => {
      if (!result) {
        req.flash('login-form-error', 'Username or password are incorrect');

        return res.redirect('/auth/login');
      }
      if (!bcrypt.compareSync(password /* provided password */, result.password/* hashed password */)) {
        req.flash('login-form-data', { username });
        req.flash('login-form-error', 'Username or password are incorrect');
        return res.redirect('/auth/login');
      }
      // Save the login in the session!
      req.session.currentUser = result;
      res.redirect('/');
    })
    .catch(next);
});

router.post('/logout', (req, res, next) => {
  delete req.session.currentUser;
});

module.exports = router;
