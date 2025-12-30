import express, { Router } from "express";
import { getUserProfile, insertUser, loginUser } from "../controllers/users-controllers";
import { requireAuth } from "../middlewares/auth.middleware";
//import "../types/express";

const router: Router = express.Router();

// router to register user
router.post("/signup", insertUser);

// router to get user profile only when logged in(protected routes)
router.get("/profile", requireAuth, getUserProfile);

// router to login in user
router.post("/login", loginUser);

export default router;