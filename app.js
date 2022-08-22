require('dotenv').config();
const express = require("express");
const bodyParser = require("body-parser")
const ejs = require("ejs");
const mongoose = require("mongoose");
const session = require('express-session');
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const FacebookStrategy = require("passport-facebook");
const findOrCreate = require('mongoose-findorcreate');

const app = express();
const port = 3000;

app.use(express.static("public"));
app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({
    extended: true
}));

app.use(session({
    secret: process.env.SECRET,
    resave: false,
    saveUninitialized: false,
}));

app.use(passport.initialize());
app.use(passport.session());

mongoose.connect("mongodb://localhost:27017/userDB");


const userSchema = new mongoose.Schema({
    email: String,
    password: String,
    googleId: String,
    facebookId: String,
    secret : String
});

userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);

const User = new mongoose.model("User", userSchema);

passport.use(User.createStrategy());

passport.serializeUser(function (user, cb) {
    process.nextTick(function () {
        cb(null, {
            id: user.id,
            username: user.username,
            name: user.name
        });
    });
});

passport.deserializeUser(function (user, cb) {
    process.nextTick(function () {
        return cb(null, user);
    });
});

passport.use(new GoogleStrategy({
        clientID: process.env.GOOGLE_APP_ID,
        clientSecret: process.env.GOOGLE_APP_SECRETS,
        callbackURL: process.env.GOOGLE_APP_CALLBACK,
        userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo"
    },
    (accessToken, refreshToken, profile, cb) => {
        console.log(profile);
        User.findOrCreate({
            googleId: profile.id
        }, function (err, user) {
            return cb(err, user);
        });
    }
));


passport.use(new FacebookStrategy({
        clientID: process.env.FACEBOOK_APP_ID,
        clientSecret: process.env.FACEBOOK_APP_SECRET,
        callbackURL: process.env.FACEBOOK_APP_CALLBACK,

    },
    (accessToken, refreshToken, profile, cb) => {
        console.log(profile);
        User.findOrCreate({
            facebookId: profile.id
        }, function (err, user) {
            return cb(err, user);
        });

    }
));

app.get("/", (req, res) => {
    res.render("home");
});

// Google Authentication 
app.get("/auth/google",
    passport.authenticate('google', {
        scope: ["profile"]
    }));

app.get("/auth/google/secrets",
    passport.authenticate('google', {
        failureRedirect: "/login"
    }),
    function (req, res) {
        // Successful authentication, redirect home.
        res.redirect("/secrets");
    });

// Facebook Authentication
app.get('/auth/facebook',
    passport.authenticate('facebook'));

app.get('/auth/facebook/secrets',
    passport.authenticate('facebook', {
        failureRedirect: "/login"
    }),
    function (req, res) {
        // Successful authentication, redirect home.
        res.redirect("/secrets");
    });


app.get("/login", (req, res) => {
    res.render("login");
});

app.get("/register", (req, res) => {
    res.render("register");
});

app.get("/secrets", (req, res) => {
    if (req.isAuthenticated()) {
        res.render("secrets");
    } else {
        res.redirect("/login");
    }
});


app.post("/register", (req, res) => {

    User.register({
            username: req.body.username
        },
        req.body.password,
        (err, user) => {
            if (err) {
                console.log(err);
                res.redirect("/register");
            } else {
                passport.authenticate("local")(req, res, () => {
                    res.redirect("/secrets");
                });
            }
        });
});

app.post("/login", (req, res) => {

    const user = new User({
        username: req.body.username,
        password: req.body.password
    });

    req.login(user, (err) => {
        if (err) {
            console.log(err);
        } else {
            passport.authenticate("local")(req, res, () => {
                res.redirect("/secrets");
            });
        }
    });

});



app.get("/logout", (req, res) => {
    req.logout((err) => {
        err ? console.log(err) : res.redirect("/");
    });
});

app.listen(port, () => {
    console.log(`Server started on port ${port}`);
});