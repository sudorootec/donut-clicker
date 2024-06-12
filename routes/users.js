const express = require("express");
const router = express.Router();
const passport = require("passport");
const LocalStrategy = require("passport-local").Strategy;
const User = require("../models/user");

// Signup page
router.get("/signup", (req, res) => {
  res.render("signup", {
    title: "Inscription - Donut Clicker",
    pageClass: 'signup'
  });
});

// Login page
router.get("/login", (req, res) => {
  res.render("login", {
    title: "Connexion - Donut Clicker",
    pageClass: 'login'
  });
});

// Signup post handler
router.post("/signup", async (req, res, next) => {
  try {
    const { username, email, password, password_c } = req.body;

    req.checkBody("username", "Username is required").notEmpty();
    req.checkBody("username", "Username Already Exist").isUniqueUsername();
    req.checkBody("email", "Email is required").notEmpty();
    req.checkBody("email", "Email is not valid").isEmail();
    req.checkBody("email", "Email already exists").isUniqueEmail();
    req.checkBody("password", "Password is required").notEmpty();
    req.checkBody("password_c", "Passwords do not match").equals(password);

    const result = await req.getValidationResult();
    if (!result.isEmpty()) {
      const errors = result.array();
      res.render("signup", { errors });
    } else {
      const newUser = new User({ username, email, password });
      await User.createUser(newUser);
      res.redirect("/users/login");
    }
  } catch (err) {
    next(err);
  }
});

// Passport local strategy setup
passport.use("local", new LocalStrategy({
  usernameField: "email",
  passwordField: "password"
}, async (email, password, done) => {
  try {
    const user = await User.getUserByEmail(email);
    if (!user) {
      return done(null, false, { message: "User not found" });
    }
    const isMatch = await User.comparePassword(password, user.password);
    if (isMatch) {
      return done(null, user);
    } else {
      return done(null, false, { message: "Incorrect password" });
    }
  } catch (err) {
    return done(err);
  }
}));

passport.serializeUser((user, done) => {
  done(null, user.id);
});

passport.deserializeUser((id, done) => {
  User.getUserById(id, (err, user) => {
    done(err, user);
  });
});

// Login post handler
router.post("/login", passport.authenticate("local", {
  successRedirect: "/",
  failureRedirect: "/users/login",
  failureFlash: true
}));

// Logout handler
router.get("/logout", (req, res) => {
  req.logout();
  req.session.destroy();
  res.redirect("/users/login");
});

module.exports = router;
