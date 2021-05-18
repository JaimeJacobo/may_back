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
const cookieSession = require("cookie-session");

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

// -------- CORS --------

app.use((req, res, next) => {
  res.header("Access-Control-Allow-Origin", "*");
  res.header(
    "Access-Control-Allow-Headers",
    "Authorization, X-API-KEY, Origin, X-Requested-With, Content-Type, Accept, Access-Control-Allow-Request-Method"
  );
  res.header("Access-Control-Allow-Methods", "GET, POST, OPTIONS, PUT, DELETE");
  res.header("Allow", "GET, POST, OPTIONS, PUT, DELETE");
  next();
});

app.use(
  cors({
    credentials: true,
    origin: [
      "http://localhost:3000",
      "https://may-front.herokuapp.com/",
      "https://may-front.herokuapp.com",
    ],
  })
);

app.set("trust proxy", 1);
app.use(
  cookieSession({
    name: "session",
    keys: ["key1", "key2"],
    sameSite: "none",
    secure: true,
  })
);
app.use(
  session({
    secret: "secret",
    resave: true,
    saveUninitialized: true,
    cookie: {
      sameSite: "none",
      secure: true,
    },
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

app.listen(PORT, () => {
  console.log(chalk.green.inverse(`Puerto activado en ${PORT}`));
});
