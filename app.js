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

app.use(flash());

app.set("trust proxy", 1);
app.use(
  cookieSession({
    name: "__session",
    keys: ["key1"],
      maxAge: 24 * 60 * 60 * 100,
      secure: true,
      httpOnly: true,
      sameSite: 'none'
  })
);


// -------- CORS --------

// app.use(
//   cors({
//     credentials: true,
//     origin: [
//       "http://localhost:3000",
//       "https://may-front.herokuapp.com/",
//       "https://may-front.herokuapp.com",
//     ],
//   })
// );

// app.use(cors());

app.use(function (req, res, next) {
  res.header("Access-Control-Allow-Origin", "https://may-front.herokuapp.com");
  res.header("Access-Control-Allow-Credentials", true);
  res.header(
    "Access-Control-Allow-Headers",
    "Origin, X-Requested-With, Content-Type, Accept"
  );
  next();
});

app.use(
  session({
    secret: `${process.env.SECRET}`,
    resave: true,
    saveUninitialized: true,
    cookie: {
      sameSite: "none",
      secure: true,
    },
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
