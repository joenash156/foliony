import { hashItem, compareHashedItem } from "../utils/hashing"
import { generateSlugSuffix } from "../utils/slug-suffix";
import db from "../configs/database";
import { Request, Response } from "express"
import { v4 as uuid } from "uuid";
import { RowDataPacket } from "mysql2";
import { signAccessToken, signRefreshToken } from "../utils/jwt";
//import "../types/express";

interface RequestBody {
  firstname?: string
  lastname?: string
  email?: string
  password?: string
}

const REFRESH_TOKEN_EXPIRY_DAYS = 7;

const expiresAt = new Date(
  Date.now() + REFRESH_TOKEN_EXPIRY_DAYS * 24 * 60 * 60 * 1000
);

// controller to register/insert user
export const insertUser = async (req: Request, res: Response): Promise<void> => {

  const { firstname, lastname, email, password }: RequestBody = req.body;

  if(!firstname || !lastname || !email || !password) {
    res.status(400).json({
      success: false,
      error: "All fields are required!"
    })

    return
  }
  
  // check if email and slug exists
  const [rows] = await db.query<RowDataPacket[]>("SELECT email FROM users WHERE email = ?", [email])
  if(rows.length > 0) {
    res.status(409).json({
      success: false,
      error: "User with this email already exists!"
    })

    return

  }

  // get the hashed password and id and form the username slug
  const id = uuid();
  const hashedPassword = await hashItem(password);
  const suggestedUsernameSlug = `${firstname?.toLowerCase()}-${lastname?.toLowerCase()}`;

  // check if suggested username slug is in use
  const [slugs] = await db.query<RowDataPacket[]>("SELECT username_slug FROM users WHERE username_slug = ?", [suggestedUsernameSlug]);

  
    // if it is in use, give user a new slug
    const usernameSlug =  slugs.length > 0 ? `${suggestedUsernameSlug}-${generateSlugSuffix()}` : suggestedUsernameSlug;
  

  // insert info into database
  try{
    await db.query("INSERT INTO users (id, firstname, lastname, email, username_slug, password_hash) VALUES (?, ?, ?, ?, ?, ?)", [id, firstname, lastname, email, usernameSlug, hashedPassword]);

    res.status(201).json({
      success: true,
      message: "User registered successfully!✅",
      user: {
        id,
        firstname,
        lastname,
        email,
        usernameSlug
      }
    })

    return
  } catch(err: unknown) {
    console.error("Failed registering user!", err)
    res.status(500).json({
      success: false,
      error: "Database error!"
    })

    return
  }
}

// controller to get user profile (protected route controller)
export const getUserProfile = async (req: Request, res: Response): Promise<void> => {
  const userId: string = req.user!.id;

  if(!userId) {
    res.status(401).json({
      success: false,
      error: "Unauthorized user!"
    })
    return
  }

  try {
    const [rows] = await db.query<RowDataPacket[]>("SELECT id, firstname, lastname, username_slug, email, other_email, phone, other_phone, avatar_url, theme_preference, bio, headline, location, role, portfolio_visibility, is_approved, last_login_at, is_profile_complete, created_at, updated_at FROM users WHERE id = ?", [userId])

    if(rows.length === 0) {
      res.status(404).json({
        success: false,
        error: "User not found!"
      });
      return;
    }

    const user = rows[0];

    res.status(200).json({
      success: true,
      message: "User found✅",
      user
    });
    return;

  } catch(err: unknown) {
    console.error("User not found: ", err);
    res.status(500).json({
      success: false,
      error: "Database error"
    });
    return;
  }
  
}

// controller to login user
export const loginUser = async (req: Request, res: Response): Promise<void>=> {

  const { email, password }: RequestBody = req.body;

  if(!email || !password) {
    res.status(400).json({
      success: false,
      error: "email and password are require for login!"
    })
    return;
  }

  try {
    const [rows] = await db.query<RowDataPacket[]>("SELECT id, firstname, lastname, username_slug, email, password_hash, other_email, phone, other_phone, avatar_url, theme_preference, bio, headline, location, role, portfolio_visibility, is_approved, last_login_at, is_profile_complete, created_at, updated_at FROM users WHERE email = ?", [email]);

    if(rows.length === 0) {
      res.status(404).json({
        success: false,
        error: "Invalid email or password!"
      });
      return;
    }

    const user = rows[0];
    // check if password is correct
    const isMatch = await compareHashedItem(password, user?.password_hash);
    if(!isMatch) {
      res.status(401).json({
        success: false,
        error: "Invalid email or password"
      });
      return;
    }

    // generate refresh and access tokens
    const accessToken = await signAccessToken({ id: user?.id, email: user?.email });
    const refreshToken = await signRefreshToken({ id: user?.id, email: user?.email })

    // store refresh token in httpOnly cookie
    res.cookie("refreshToken", refreshToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production" ? true : false,
      sameSite: process.env.NODE_ENV === "production" ? "none" : "lax",
      path: "/",
      maxAge: 7 * 24 * 60 * 60 * 1000
    });

    // hash refresh token
    const hashedRefreshToken = await hashItem(refreshToken);

    const id = uuid();

    // insert hashed refresh token into database
    await db.query("INSERT INTO refresh_tokens (id, user_id, token_hash, expires_at) VALUES (?, ?, ? ,?)", [id, user?.id, hashedRefreshToken, expiresAt]);

    res.status(200).json({
      success: true,
      message: "User logged in successfully!✅",
      accessToken,
      user
    })
    return;

  } catch(err) {
    console.error("Failed to login!", err);
    res.status(500).json({
      success: false,
      error: "Database error!"
    });
    return;
  }
}