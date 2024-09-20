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
router.get("/getCurrentUser", userController.verifyJWT, userController.getCurrentUser);
router.post("/refreshToken", userController.refreshToken);

// Tasks
router.post("/tasks", userController.verifyJWT, userController.createTask);
router.get("/tasks", userController.verifyJWT, userController.getCurrentUserTask);
router.get("/allTasks", userController.verifyJWT, userController.getAllTasks);
router.put("/tasks/:id", userController.verifyJWT, userController.updateTask);
router.delete("/tasks/:id", userController.verifyJWT, userController.deleteTask);

module.exports = router;