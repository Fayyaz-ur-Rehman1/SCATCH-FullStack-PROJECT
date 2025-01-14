const userModel = require("../models/user-modle");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const { genrateToken } = require("../utils/generateToken");


async function registerUser(req, res) {
    try {
        let { email, password, fullname } = req.body;

        let user = await userModel.findOne({ email: email });
        if (user) {
            req.flash("You already have an account , please login.");
            return res.redirect("/");
        }

        bcrypt.genSalt(10, (err, salt) => {

            bcrypt.hash(password, salt, async (err, hash) => {

                if (err) return res.send(err.message);
                else {
                    let user = await userModel.create({
                        email,
                        password: hash,
                        fullname,
                    });

                    let token = genrateToken(user);
                    res.cookie("token", token);
                    // res.send("user created successfully");
                }
            })
        })

    } catch (err) {
        res.send(err);
    }
}

async function loginUser(req, res) {
    let { email, password } = req.body;

    let user = await userModel.findOne({ email: email });
    if (!user) {
        req.flash("error", "Email or Password incorrect");
    }

    bcrypt.compare(password, user.password, (err, result) => {
        if (result) {
            let token = genrateToken(user);
            res.cookie("token", token);
        } else {
            req.flash("Email or Password incorrect");
            return res.redirect("/");
        }
    })

}

async function logout(req, res) {
    res.cookie("token", "");
    res.redirect("/");
}

module.exports = {
    registerUser,
    loginUser,
    logout,
}