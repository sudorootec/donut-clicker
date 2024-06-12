const express = require('express');
const bcrypt = require("bcrypt");
const router = express.Router();
const User = require("../models/user");

/* GET home page. */
router.get('/', ensureAuthenticated, async (req, res, next) => {
  try {
    res.render('index', {
      title: 'Donut Clicker',
      user: req.user
    });
  } catch (err) {
    next(err);
  }
});

router.post('/', async (req, res, next) => {
  try {
    const id = req.body.id;
    const username = req.body.username;
    const email = req.body.email;
    const password = req.body.password;

    const user = await User.findById(id);
    if (!user) {
      throw new Error('User not found');
    }

    if (user.username !== username || user.email !== email || password.length !== 0) {
      if (user.username !== username) {
        req.checkBody("username", "Username is required").notEmpty();
        req.checkBody("username", "Username Already Exist").isUniqueUsername();
      }
      if (user.email !== email) {
        req.checkBody("email", "Email is required").notEmpty();
        req.checkBody("email", "Email is not valid").isEmail();
        req.checkBody("email", "Email already exists").isUniqueEmail();
      }
      const result = await req.getValidationResult();
      if (!result.isEmpty()) {
        const errors = result.array();
        res.render("index", { errors });
      } else {
        const salt = await bcrypt.genSalt(10);
        const hash = await bcrypt.hash(password, salt);
        user.username = username;
        user.email = email;
        if (password.length !== 0) {
          user.password = hash;
        }
        await user.save();
        res.redirect(req.originalUrl);
      }
    }
  } catch (err) {
    next(err);
  }
});

router.get('/backup', async (req, res, next) => {
  try {
    const userId = req.query.id;
    if (!userId) {
      throw new Error('Undefined user');
    }

    const user = await User.getUserById(userId);
    if (!user) {
      throw new Error('User not found');
    }

    res.json({ backup: user.backup });
  } catch (err) {
    next(err);
  }
});

router.put('/save', async (req, res, next) => {
  try {
    const userId = req.body.id;
    if (!userId) {
      throw new Error('Undefined user');
    }

    const user = await User.getUserById(userId);
    if (!user) {
      throw new Error('User not found');
    }

    user.backup = req.body.backup;
    await user.save();
    res.json({ saved: true });
  } catch (err) {
    next(err);
  }
});

router.get('/forgot_password', (req, res) => {
  res.render('forgot', {
    title: 'Forgot password - Donut Clicker',
    pageClass: 'forgot'
  });
});

router.post('/forgot_password', async (req, res, next) => {
  try {
    const { email, password, password_c } = req.body;
    if (email.length > 0 && password.length > 0 && password === password_c) {
      const user = await User.getUserByEmail(email);
      if (!user) {
        throw new Error('User not found');
      }

      const salt = await bcrypt.genSalt(10);
      const hash = await bcrypt.hash(password, salt);
      user.password = hash;
      await user.save();
      res.redirect('/users/login');
    } else {
      res.redirect('/forgot_password');
    }
  } catch (err) {
    next(err);
  }
});

function ensureAuthenticated(req, res, next) {
  if (req.isAuthenticated()) {
    return next();
  } else {
    res.redirect('/users/login');
  }
}

module.exports = router;
