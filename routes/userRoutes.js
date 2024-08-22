const express = require("express");
const userController = require("./../controllers/userController");

const router = express.Router();

// Authentication
router.post("/register", userController.register);
router.post("/login", userController.login);
router.post("/forgotPassword", userController.forgotPassword);
router.post("/verifyOTP", userController.verifyOTP);
router.post("/updatePassword", userController.verifyJWT, userController.updatePassword);
router.get("/viewProfile", userController.verifyJWT, userController.viewProfile);

// Tasks
router.post("/tasks", userController.verifyJWT, userController.createTask);

module.exports = router;