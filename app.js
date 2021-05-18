require("dotenv").config();

const bodyParser = require("body-parser");
const cookieParser = require("cookie-parser");
const express = require("express");
const chalk = require("chalk");
const cors = require("cors");
const bcrypt = require("bcrypt");
const flash = require("connect-flash");
const session = require("express-session");
const passport = require("passport");
const LocalStrategy = require("passport-local").Strategy;

// -------- PORT --------
const PORT = process.env.PORT || 5000;

// -------- MODELS --------
const User = require("./models/User.models");

// -------- MONGOOSE --------
require("./configs/mongoose");

const app = express();

// -------- Middleware setup --------
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: false }));
app.use(cookieParser());

const path = require("path");
app.use(express.static(path.join(__dirname, "public")));

// -------- CORS --------

app.use(
  cors({
    methods: ["GET", "POST"],
    credentials: true,
    origin: ["http://localhost:3000", "https://may-front.herokuapp.com"],
  })
);

// -------- PASSPORT --------
app.use(
  session({
    secret: process.env.SECRET,
    resave: true,
    saveUninitialized: true,
  })
);

passport.serializeUser((user, callback) => {
  callback(null, user._id);
});

passport.deserializeUser((id, callback) => {
  User.findById(id)
    .then((result) => {
      callback(null, result);
    })
    .catch((err) => {
      callback(err);
    });
});

app.use(flash());

passport.use(
  new LocalStrategy(
    {
      usernameField: `username`,
      passwordField: `password`,
      passReqToCallback: true,
    },
    (req, username, password, next) => {
      User.findOne({ username })
        .then((user) => {
          if (!user) {
            return next(null, false, {
              message: `Incorrect username or password`,
            });
          }
          if (!bcrypt.compareSync(password, user.password)) {
            return next(null, false, {
              message: `Incorrect username or password`,
            });
          }
          return next(null, user);
        })
        .catch((err) => {
          next(err);
        });
    }
  )
);

app.use(passport.initialize());
app.use(passport.session());

app.use("/", require("./routes/index.routes"));
app.use("/auth", require("./routes/auth.routes"));

app.use((req, res, next) => {
  // If no routes match, send them the React HTML.
  res.sendFile(__dirname + "/public/index.html");
});

app.listen(PORT, () => {
  console.log(chalk.green.inverse(`Puerto activado en ${PORT}`));
});
