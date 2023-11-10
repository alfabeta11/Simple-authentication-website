import "dotenv/config";
import express from "express";
import bodyParser from "body-parser";
import pg from "pg";
import bcrypt from "bcrypt";
import session from "express-session";
import passport from "passport";
import LocalStrategy from "passport-local";
import GoogleStrategy from "passport-google-oauth20";

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

// initialize our passport
app.use(passport.initialize());
app.use(passport.session());

// Defining a local strategy;
passport.use(
  new LocalStrategy(async function verify(username, password, cb) {
    try {
      // Checking if user exist in db
      const result = await db.query("SELECT * FROM users WHERE username = $1", [
        username,
      ]);
      const user = result.rows[0];
      if (!user) {
        return cb(err);
      }
      // If user exist, check if password matches
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
// Serializer
passport.serializeUser(function (user, cb) {
  process.nextTick(function () {
    return cb(null, {
      id: user.id,
      username: user.username,
      password: user.password,
    });
  });
});
// Deserializer
passport.deserializeUser(function (user, cb) {
  process.nextTick(function () {
    return cb(null, user);
  });
});
// Google authentication strategy
passport.use(new GoogleStrategy({
  clientID: process.env.OAUTH_ID,
  clientSecret: process.env.OAUTH_SECRET,
  callbackURL: "http://localhost:3000/oauth/google/secrets"
},  async function(a, b, profile, cb) {
  let user = {};
  const result = await db.query("SELECT * FROM users WHERE username = $1",[profile.id]);
  let data = result.rows;
  if (!data) {
    try {
      let addUser = await db.query("INSERT INTO users (username) VALUES ($1) RETURNING * ", [profile.id]);
      let newUser = addUser.rows[0];
      user = newUser;
    } catch(err) {
      console.log("Could not add user.");
      cb(null, err);
    }
  } else {
    user = data[0];
  }
  cb(null, user);
}));

// homepage
app.get("/", (req, res) => {
  res.render("home.ejs");
});
// sign-in with google
app.get("/auth/google", passport.authenticate("google", { scope: ["profile"] }));
// page to redirect after google sign-in
app.get('/oauth/google/secrets', passport.authenticate('google', {
  failureRedirect: '/login'
}), (req, res) => {
  res.redirect("/secrets")
});
// login page
app.get("/login", (req, res) => {
  res.render("login.ejs");
});
// register page
app.get("/register", (req, res) => {
  res.render("register.ejs");
});
// register request
app.post("/register", (req, res) => {
  bcrypt.hash(
    req.body.password,
    parseInt(process.env.SALT_ROUNDS),
    async function (err, hash) {
      // Store hash in your password DB.
      try {
        await db.query("INSERT INTO users (username, password) VALUES ($1, $2)", [
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
// the secret page to access if user registered/signed-in
app.get("/secrets", (req, res) => {
  // If user is authenticated, render secrets.ejs
  if (req.isAuthenticated()) {
    res.render("secrets.ejs");
  } else {
    // If not authenticated we redirect to /login
    res.redirect("/login");
  }
});
// login request
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
// logout from session
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
