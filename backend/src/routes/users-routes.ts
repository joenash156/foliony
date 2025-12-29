import express, { Router } from "express";
import { getUserProfile, insertUser } from "../controllers/users-controllers";
import { requireAuth } from "../middlewares/auth.middleware";

const router: Router = express.Router();

// router to register user
router.post("/signup", insertUser);

// router to get user profile only when logged in(protected routes)
router.get("/profile", requireAuth, getUserProfile);

export default router;