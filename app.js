//jshint esversion:6
/* 
commit 98ce8958d78eadfeb37cc7fb95c41cadf86fbd4f
Level 6 - Google OAuth 2.0 Authentication
using OAuth we can access third party data depending on other company 
and aauthenticate the user
why auth?
=> Granular level access- it gives access to only certain things like 
contacts photos
=> read write data
=> Revoke access from third party website
Steps:-
--------
1) Setup
2) redirect and authenticate
3) user logins
4) user grants permission
5) after all this is done on third party till will provide us auth code/acess token
auth code - only works one time
access token - like a yr pass

commit 4e8349702f16a5570f9ff9b80f7a3740ddd8b108
Level 5 - Cookies and Sessions

 
commit d3b3b3a908fc01e72b99616db45e2c28f8975369
Level 4 - Hashing and Salting with bcrypt
https://haveibeenpwned.com 
=>salt is a random numb 
pass + salt => hash + salt => hash + salt => hash (salt rounds)
thorugh this same hash password prblm is solved
=>bcrypt is salt rounds
install the older version of bcrypt if latest is not working

commit 17696f8cfe68c8f91082a98e9750d45e9e176bc3
Level 3 - Hashing with md5
Hashing is a concept where the data is converted easily into hash but returning
back to original data is almost impossible therefore, when user registers the
password is converted to hash and then login then again converted to hash
and then the two hashes are compared to check the validity. ex-377
 
commit 92a07aa559eb29e5c9c0f50304e7b5e0674a25d1
Add Environment Vars
 
commit 1702e1d3f75bfbeb0e43848c8bd921863ea21147
 Level 2 - Encryption
 exchanging letters and words which can only be encrpted if 
 we know the key to it.
 
commit 7078af837299a4ff50121d67afe17d9fa522ec68
Level 1 - Username and Password Only
*/
//setup at the very top
require("dotenv").config();
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require("mongoose");
const session = require("express-session");
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");
const GoogleStrategy = require("passport-google-oauth20").Strategy;
const findOrCreate = require("mongoose-findorcreate");
// const bcrypt = require("bcrypt");
// const saltRounds = 10;
// const md5 = require("md5");
// const encrypt = require("mongoose-encryption");
const app = express();

// console.log(process.env.KEY); //to print.
app.use(bodyParser.urlencoded({extended:true}));
app.use(express.static("public"));
app.set("view engine","ejs");
app.use(session({
    secret: "Our little secret",
    resave: false,
    saveUninitialized: false
}));

app.use(passport.initialize());
app.use(passport.session());

mongoose.connect("mongodb://localhost:27017/userDB");
mongoose.set("useCreateIndex",true);

//schema need to be changed
const userSchema= new mongoose.Schema({
    email:String,
    password:String,
    googleId:String,
    secret:String
})

userSchema.plugin(passportLocalMongoose);
//do this before creating model as updated one will send to model creation

// userSchema.plugin(encrypt,{secret:process.env.SECRET, encryptedFields: ["password"]}); //for adding multiple fields just add values in array
userSchema.plugin(findOrCreate);

const User = new mongoose.model("user",userSchema);

passport.use(User.createStrategy());
//for mongoose pckg
// passport.serializeUser(User.serializeUser());
// passport.deserializeUser(User.deserializeUser());

//for passport pckg
passport.serializeUser(function(user, done) {
    done(null, user.id);
  });
  
  passport.deserializeUser(function(id, done) {
    User.findById(id, function(err, user) {
      done(err, user);
    });
  });

passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:3500/auth/google/secrets",
    userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo"
  },
  function(accessToken, refreshToken, profile, cb) {
    User.findOrCreate({ googleId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));

app.get("/",function(req,res){
    res.render("home")
})
app.get("/auth/google",
    passport.authenticate("google",{scope: ["profile"]})
)
app.get('/auth/google/secrets', 
  passport.authenticate('google', { failureRedirect: '/login' }),
  function(req, res) {
    // Successful authentication, redirect home.
    res.redirect('/secrets');
});
app.get("/register",function(req,res){
    res.render("register");
})
app.get("/login",function(req,res){
    res.render("login");
})
app.get("/secrets",function(req,res){
    User.find({"secret": {$ne:null}},function(err,foundUsers){
        if(err){
            console.log(err);
        }
        else{
            if(foundUsers){
                res.render("secrets",{userWithSecrets: foundUsers})
            }
        }
    })
})
app.get("/logout",function(req,res){
    req.logout();
    res.redirect("/");
})
app.get("/submit",function(req,res){
    if(req.isAuthenticated()){
        res.render("submit");
    }
    else{
        res.redirect("/login");
    }
})
app.post("/submit",function(req,res){

    const submittedSecret = req.body.secret;
    User.findById(req.user.id,function(err,foundUser){
        if(err){
            console.log(err);
        }
        else{
            if(foundUser)
            {
                foundUser.secret = submittedSecret;
                foundUser.save(function(){
                    res.redirect("/secrets");
                });
            }
        }
    })

})
//LEVEL 1 Auth (SIGNUP FIELD)
app.post("/register",function(req,res){

    // bcrypt.hash(req.body.password,saltRounds,function(err,hash){
    //     const newUser = new User({
    //         email:req.body.username,
    //         password:hash
    //     });
    //     //automatically behind the scenes it will encrypt the data
    //     newUser.save(function(err){
    //         if(!err){
    //             res.render("secrets");
    //         }
    //         else
    //         {
    //             res.send(err);
    //             console.log(err);
    //         }
    //     })
    // })
    User.register({username: req.body.username}, req.body.password,function(err,user){
        if(err)
        {
            console.log(err);
            res.redirect("/register");
        }
        else{
            passport.authenticate("local")(req,res,function(){
                res.redirect("/secrets");
            })
        }
    })
    
})

app.post("/login",function(req,res){
    // const Username = req.body.username;
    // const Password = req.body.password;
    // //automatically will decrypt the data
    // User.findOne({email:Username},function(err,foundUser){
    //     if(!err)
    //     {
    //         if(foundUser)
    //         {
    //             bcrypt.compare(Password,foundUser.password,function(err,result){
    //                 if(result === true)
    //                 {
    //                     res.render("secrets");
    //                 }
    //             })
                
    //         }
    //     }
    //     else{
    //         res.send(err);
    //     }
    // })
    const user = new User({
        username: req.body.username,
        password: req.body.password
    })
    req.login(user,function(err){
        if(err){
            console.log(err);
        }
        else{
            passport.authenticate("local") (req,res,function(){
                res.redirect("/secrets");
            })
        }
    })
})

app.listen(3500,function(){
    console.log("authentication server started");
})
