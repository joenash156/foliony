import express, { Router } from "express";
import { deleteUser, getUserProfile, insertUser, loginUser, updateUserProfile } from "../controllers/users-controllers";
import { requireAuth } from "../middlewares/auth.middleware";
//import "../types/express";

const router: Router = express.Router();

// router to register user
router.post("/signup", insertUser);

// router to get user profile only when logged in (protected route)
router.get("/profile", requireAuth, getUserProfile);

// router to login in user
router.post("/login", loginUser);

// router to update user profile only when logged in (protected route)
router.patch("/update_profile", requireAuth, updateUserProfile);

// router to delete user when logged in (protected route)
router.delete("/delete", requireAuth, deleteUser);

export default router;