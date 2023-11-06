import 'dotenv/config';
import express from "express";
import bodyParser from "body-parser";
import pg from "pg";

const db = new pg.Client({
    user: process.env.PG_USER,
    password: process.env.PG_PASSWORD,
    database: process.env.PG_DB,
    host: "localhost",
    port: 5432
});
db.connect();

const app = express();
const port = 3000;

app.use(express.static("public"));
app.use(bodyParser.urlencoded({extended: true}));

app.get("/", (req, res) => {
    res.render("home.ejs")
});
app.get("/login", (req, res) => {
    res.render("login.ejs")
})
app.get("/register", (req, res) => {
    res.render("register.ejs");
})
app.get("/logout", (req, res) => {
    res.render("home.ejs");
})
app.post("/register", async (req, res) => {
    const newUser = {
        email: req.body.username,
        password: req.body.password
    };
    try {
        await db.query("INSERT INTO users (email, password) VALUES ($1, $2)", [newUser.email, newUser.password]);
        res.render("secrets.ejs");
    } catch (err) {
        console.log(err);
    }

})
app.post("/login", async (req, res) => {
    const username = req.body.username;
    const password = req.body.password;
    
    try {
        let result = await db.query("SELECT * FROM users WHERE email = $1", [username]);
        let data = result.rows;

        if (data.length > 0 && data[0]["password"] === password) {
            res.render("secrets.ejs");
        } else {
            throw new Error("User does not exist!");
        }
    } catch (err) {
        console.log(err.message);
        res.render("login.ejs");
    }
})
app.listen(port, () => {
    console.log("Server running on port " + port);
})