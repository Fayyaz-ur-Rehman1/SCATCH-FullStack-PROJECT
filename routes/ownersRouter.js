const express = require("express");
const router = express.Router();
const ownerModels = require("../models/owner-model");

if (process.env.NODE_ENV = "development") {
    router.post("/create", async (req, res) => {

        let owners = await ownerModels.find({});
        if (owners.length > 0) {
            return res.status(503).send("you don't have permission to create a new owner");
        }

        let { fullname, email, password } = req.body;

        let createOwner = await ownerModels.create({
            fullname,
            email,
            password,
        })

        res.status(201).send(createOwner);
    });
}


router.get("/", (req, res) => {
    res.send("hey");
});

module.exports = router;