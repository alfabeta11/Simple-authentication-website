import "dotenv/config";
import express from "express";
import bodyParser from "body-parser";
import pg from "pg";
import bcrypt from "bcrypt";
import session from "express-session";
import passport from "passport";
import LocalStrategy from "passport-local";

const db = new pg.Client({
  user: process.env.PG_USER,
  password: process.env.PG_PASSWORD,
  database: process.env.PG_DB,
  host: "localhost",
  port: 5432,
});
db.connect();

const app = express();
const port = 3000;

app.use(express.static("public"));
app.use(bodyParser.urlencoded({ extended: true }));

app.use(
  session({
    secret: process.env.SECRET,
    resave: false,
    saveUninitialized: false,
  })
);

// initialize passport
app.use(passport.initialize());
app.use(passport.session());
// app.use(passport.authenticate("session"));

// Defining a strategy;
passport.use(
  new LocalStrategy(async function verify(username, password, cb) {
    try {
      const result = await db.query("SELECT * FROM users WHERE email = $1", [
        username,
      ]);
      const user = result.rows[0];
      if (!user) {
        return cb(err);
      }
      const match = await bcrypt.compare(password, user["password"]);
      if (!match) {
        return cb((null, false, { message: "Incorrect password" }));
      } else {
        return cb(null, user);
      }
    } catch (err) {
      return cb(err);
    }
  })
);

passport.serializeUser(function (user, cb) {
  process.nextTick(function () {
    return cb(null, {
      id: user.id,
      username: user.username,
      password: user.password,
    });
  });
});

passport.deserializeUser(function (user, cb) {
  process.nextTick(function () {
    return cb(null, user);
  });
});

app.get("/", (req, res) => {
  res.render("home.ejs");
});

app.get("/login", (req, res) => {
  res.render("login.ejs");
});

app.get("/register", (req, res) => {
  res.render("register.ejs");
});

app.post("/register", (req, res) => {
  bcrypt.hash(
    req.body.password,
    parseInt(process.env.SALT_ROUNDS),
    async function (err, hash) {
      // Store hash in your password DB.
      try {
        await db.query("INSERT INTO users (email, password) VALUES ($1, $2)", [
          req.body.username,
          hash,
        ]);
        // Saving cookie when registering completed
        passport.authenticate("local")(req, res, function () {
          res.redirect("/secrets");
        });
      } catch (err) {
        console.log(err);
        res.redirect("/register");
      }
      if (err) {
        console.log(err);
        res.redirect("/register");
      }
    }
  );
});

app.get("/secrets", (req, res) => {
  // If user is authenticated, render secrets.ejs
  if (req.isAuthenticated()) {
    res.render("secrets.ejs");
  } else {
    // If not authenticated we redirect to /login
    res.redirect("/login");
  }
});

app.post("/login", (req, res) => {
  const newUser = {
    username: req.body.username,
    password: req.body.password,
  };
  req.login(newUser, function (err) {
    if (err) {
      return next(err);
    }
    return res.redirect("/secrets");
  });
});

app.get("/logout", (req, res, next) => {
  req.logout(function (err) {
    if (err) {
      return next(err);
    }
    res.redirect("/");
  });
});

app.listen(port, () => {
  console.log("Server running on port " + port);
});
