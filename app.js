const express = require("express");
const bodyParser = require("body-parser")
const ejs = require("ejs");


const app = express();
const port = 3000;

app.use(express.static("public"));
app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({
    extended : true
}));

app.get("/", (req,res) =>{
    res.render("home");
})

app.get("/login", (req,res) =>{
    res.render("login");
})

app.get("/register", (req,res) =>{
    res.render("register");
})

app.get("/logout", (req,res) =>{
    res.render("home")
})

app.listen(port, () =>{
    console.log(`Server started on port ${port}`);
})