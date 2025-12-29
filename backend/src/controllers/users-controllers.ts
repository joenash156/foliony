import { hashItem } from "../utils/hashing"
import { generateSlugSuffix } from "../utils/slug-suffix";
import db from "../configs/database";
import { Request, Response } from "express"
import { v4 as uuid } from "uuid";
import { RowDataPacket } from "mysql2";

interface RequestBody {
  firstname: string
  lastname: string
  email: string
  password: string
}

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
    const [rows] = await db.query<RowDataPacket[]>("SELECT id, firstname, lastname, username_slug, email, other_email, phone, other_phone, avatar_url, theme_preference, role, is_approved, created_at, updated_at WHERE id = ?", [userId])

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