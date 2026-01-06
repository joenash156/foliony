import { hashItem, compareHashedItem } from "../utils/hashing"
import { generateSlugSuffix } from "../utils/slug-suffix";
import db from "../configs/database";
import { Request, Response } from "express"
import { v4 as uuid } from "uuid";
import { ResultSetHeader, RowDataPacket } from "mysql2";
import { signAccessToken, signRefreshToken, verifyRefreshToken } from "../utils/jwt";


interface RequestBody {
  firstname: string
  lastname: string
  othername: string | null
  email: string
  password: string
  usernameSlug: string
  otherEmail: string
  phone: string
  otherPhone: string
  bio: string
  headline: string
  location: string
  role: string
  portfolioVisibility: string
  newPassword: string
  themePreference: string
}

const REFRESH_TOKEN_EXPIRY_DAYS = 7;

const expiresAt = new Date(
  Date.now() + REFRESH_TOKEN_EXPIRY_DAYS * 24 * 60 * 60 * 1000
);

// controller to register/insert user
export const insertUser = async (req: Request, res: Response): Promise<void> => {

  const { firstname, lastname, othername, email, password }: RequestBody = req.body;

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

  const sanitizedFirstname = firstname.trim().toLowerCase();
  const sanitizedLastname = lastname.trim().toLowerCase();
  const sanitizedOthername = othername?.trim().toLowerCase();

  const suggestedUsernameSlug = sanitizedOthername
    ? `${sanitizedFirstname}-${sanitizedOthername}-${sanitizedLastname}`
    : `${sanitizedFirstname}-${sanitizedLastname}`;

  // check if suggested username slug is in use
  const [slugs] = await db.query<RowDataPacket[]>("SELECT username_slug FROM users WHERE username_slug = ?", [suggestedUsernameSlug]);

  
  // if it is in use, give user a new slug
  const usernameSlug =  slugs.length > 0 ? `${suggestedUsernameSlug}-${generateSlugSuffix()}` : suggestedUsernameSlug;

  // dynamically set the database query in case othername is null
  let insertQuery: string;
  let params: (string | null)[];

  if(othername) {
    insertQuery = "INSERT INTO users (id, firstname, lastname, other_name, email, username_slug, password_hash) VALUES (?, ?, ?, ?, ?, ?, ?)";
    params = [id, firstname, lastname, othername, email, usernameSlug, hashedPassword];
  } else {
      insertQuery = "INSERT INTO users (id, firstname, lastname, email, username_slug, password_hash) VALUES (?, ?, ?, ?, ?, ?)";
      params = [id, firstname, lastname, email, usernameSlug, hashedPassword];
    }

  // insert info into database
  try{
    await db.query<ResultSetHeader>(insertQuery, params);

    res.status(201).json({
      success: true,
      message: "User registered successfully!✅",
      user: {
        id,
        firstname,
        othername,
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
      error: "Failed registering user. Internal server error!"
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
    const [rows] = await db.query<RowDataPacket[]>("SELECT id, firstname, lastname, other_name, username_slug, email, other_email, phone, other_phone, avatar_url, theme_preference, bio, headline, location, role, portfolio_visibility, is_approved, last_login_at, is_profile_complete, created_at, updated_at FROM users WHERE id = ?", [userId])

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
      error: "User not found. Internal server error"
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
    const [rows] = await db.query<RowDataPacket[]>("SELECT * FROM users WHERE email = ?", [email]);

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

    // update last login column right after the login
    await db.query("UPDATE users SET last_login_at = NOW() WHERE id = ?", [user?.id])
    // fetch it again to return in response
    const [updatedCol] = await db.query<RowDataPacket[]>("SELECT last_login_at FROM users WHERE id = ?", [user?.id])

    const lastLoginAt = updatedCol[0]?.last_login_at;

    res.status(200).json({
      success: true,
      message: "User logged in successfully!✅",
      accessToken,
      user: {
        id: user?.id,
        firstname: user?.firstname,
        lastname: user?.lastname,
        othername: user?.other_name,
        username_slug: user?.username_slug,
        email: user?.email,
        other_email: user?.other_email,
        phone: user?.phone,
        other_phone: user?.other_phone,
        avatar_url: user?.avatar_url,
        theme_preference: user?.theme_preference,
        bio: user?.bio,
        headline: user?.headline,
        location: user?.location,
        role: user?.role,
        portfolio_visibility: user?.portfolio_visibility,
        is_approved: user?.is_approved,
        last_login_at: lastLoginAt,
        is_profile_complete: user?.is_profile_complete,
        created_at: user?.created_at,
        updated_at: user?.updated_at
      }
    })
    return;

  } catch(err) {
    console.error("Failed to login!", err);
    res.status(500).json({
      success: false,
      error: "Failed to login user. Internal server error!"
    });
    return;
  }
}

// controller to update user profile (dynamically)
export const updateUserProfile = async (req: Request, res: Response): Promise<void> => {
  const userId: string = req.user!.id;
  const { firstname, lastname, othername, usernameSlug, otherEmail, phone, otherPhone, bio, headline, location, role, portfolioVisibility}: RequestBody = req.body;

  try {
    const [rows] = await db.query<RowDataPacket[]>("SELECT id FROM users WHERE id = ?", [userId]);
    if(rows.length === 0) {
      res.status(404).json({
        success: false,
        error: "No user found to update profile"
      })
      return
    }

    const fields: (string | null)[] = [];
    const values: (string | null)[] = [];

    if(firstname !== undefined) {
      fields.push("firstname = ?");
      values.push(firstname);
    }
    if(lastname !== undefined) {
      fields.push("lastname = ?");
      values.push(lastname);
    }
    if(othername !== undefined) {
      fields.push("other_name = ?");
      values.push(othername);
    }
    if(usernameSlug !== undefined) {
      fields.push("username_slug = ?");
      values.push(usernameSlug);
    }
    if(otherEmail !== undefined) {
      fields.push("other_email = ?");
      values.push(otherEmail);
    }
    if(phone !== undefined) {
      fields.push("phone = ?");
      values.push(phone);
    }
    if(otherPhone !== undefined) {
      fields.push("other_phone = ?");
      values.push(otherPhone);
    }
    if(bio !== undefined) {
      fields.push("bio = ?");
      values.push(bio)
    }
    if(headline !== undefined) {
      fields.push("headline = ?");
      values.push(headline)
    }
    if(location !== undefined) {
      fields.push("location = ?");
      values.push(location);
    }
    if(role !== undefined) {
      fields.push("role = ?");
      values.push(role);
    }
    if(portfolioVisibility !== undefined) {
      fields.push("portfolio_visibility = ?");
      values.push(portfolioVisibility);
    }

    if(fields.length === 0) {
      res.status(400).json({
        success: false,
        error: "No field provided to update user profile"
      })
      return;
    }

    values.push(userId);

    await db.query<ResultSetHeader>(`UPDATE users SET ${fields.join(", ")} WHERE id = ?`, values);

    const [user] = await db.query<RowDataPacket[]>("SELECT id, firstname, lastname, other_name, username_slug, email, other_email, phone, other_phone, avatar_url, theme_preference, bio, headline, location, role, portfolio_visibility, is_approved, last_login_at, is_profile_complete, created_at, updated_at FROM users WHERE id = ?", [userId]);

    res.status(200).json({
      success: true,
      message: "User profile updated successfully!✅",
      user: user[0]
    })
    return;
  } catch(err: unknown) {
    console.error("Failed to update user profile: ", err)
    res.status(500).json({
      success: false,
      error: "Failed to update user profile. Internal server error!"
    })
    return;
  }

  
}

// controller to delete user account
export const deleteUser = async (req: Request, res: Response): Promise<void> => {
  const userId: string = req.user!.id;
  const { password }: RequestBody = req.body;

  if(!password) {
    res.status(400).json({
      success: false,
      error: "Password is required to delete your account!"
    })
    return;
  }

  try{
    const [rows] = await db.query<RowDataPacket[]>("SELECT password_hash FROM users WHERE id = ?", [userId]);

    if(rows.length === 0) {
      res.status(404).json({
        success: false,
        error: "user not found!"
      })
      return;
    }

    const user = rows[0];

    // if user exists, we verify the user passowrd entered
    const isMatch = await compareHashedItem(password, user?.password_hash);

    if(!isMatch) {
      res.status(401).json({
        success: false,
        error: "Password entered is incorrect!"
      })
      return;
    }

    // delete user from the datebase
    const [results] = await db.query<ResultSetHeader>("DELETE FROM users WHERE id = ?", [userId]);

    if(results.affectedRows === 0) {
      res.status(404).json({
        success: false,
        error: "Unable to delete user!"
      })
      return;
    }

    res.status(200).json({
      success: true,
      message: "User deleted successfully!✅",
    })
    return;

  } catch(err: unknown) {
    console.error("Failed to delete user!: ", err);
    res.status(500).json({
      success: false,
      error: "Failed to delete user. Internal server error"
    });
    return;
  }

}

// controller to change user password
export const changePassword = async (req: Request, res: Response): Promise<void> => {
  const userId: string = req.user!.id;
  const { password, newPassword }: RequestBody = req.body;

  if(!password || !newPassword) {
    res.status(400).json({
      success: false,
      error: "Password and new password are required!"
    })
    return;
  }
  // make a query to veridy old password
  try {
    const [rows] = await db.query<RowDataPacket[]>("SELECT password_hash FROM users WHERE id = ?", [userId]);

    if(rows.length === 0) {
      res.status(404).json({
        success: false,
        error: "No user found with the password!"
      })
      return;
    }

    const user = rows[0];

    // check to see if password entered is correct
    const isMatch = await compareHashedItem(password, user?.password_hash);

    if(!isMatch) {
      res.status(401).json({
        success: false,
        error: "Password is incorrect!"
      })
      return;
    }

    // hash the updated password
    const hashedUpdatedPassword = await hashItem(newPassword);

    // insert new password into database
    const [results] = await db.query<ResultSetHeader>("UPDATE users SET password_hash = ? WHERE id = ?", [hashedUpdatedPassword, userId]);

    if(results.affectedRows === 0) {
      res.status(401).json({
        success: false,
        error: "Unable to update user password. Try again!"
      });
      return;
    }

    res.status(200).json({
      success: true,
      message: "User password changed successfully!✅"
    });
    return;

  } catch(err: unknown) {
      console.error("Failed to update user password! ", err);
      res.status(500).json({
        success: false,
        error: "Failed to update user password. Internal server error"
      });
      return;
  }

}

// controller to change user theme preference
export const changeThemePreference = async (req: Request, res: Response): Promise<void> => {

  const userId: string = req.user!.id;
  const  { themePreference }: RequestBody = req.body;

  if(!themePreference) {
    res.status(400).json({
      success: false,
      error: "A theme is required! (e.g. light, dark, system)"
    });
    return;
  }

  try {
    await db.query<ResultSetHeader>("UPDATE users SET theme_preference = ? WHERE id = ?", [themePreference, userId]);

    // get the update theme from the database
    const [rows] = await db.query<RowDataPacket[]>("SELECT id, email, theme_preference FROM users WHERE id = ?", [userId]);

    res.status(200).json({
      success: true,
      message: "User theme update successfully!✅",
      user: rows[0]
    });
    return;

  } catch(err: unknown) {
      console.error("Failed to update user theme: ", err);
      res.status(500).json({
        success: false,
        error: "Failed to update user theme. Internal server error"
      });
      return;
  } 

}

// controller to generate new access token with existing refresh token
export const generateNewAccessToken = async (req: Request, res: Response): Promise<void> => {
  const { refreshToken }: { refreshToken?:string } = req.cookies;
  
  if(!refreshToken) {
    res.status(400).json({
      success: false,
      error: "Refresh token is required!"
    })
    return;
  }

  try {
    // verify refresh token
    const payload = await verifyRefreshToken(refreshToken);
  
    const [rows] = await db.query<RowDataPacket[]>("SELECT id, user_id, token_hash, expires_at, is_revoked FROM refresh_tokens WHERE user_id = ? AND is_revoked = 0", [payload?.id]);

    let matchedRefreshToken: RowDataPacket | null = null;

    for(const row of rows) {
      const isMatch = await compareHashedItem(refreshToken, row.token_hash);
      if(isMatch) {
        matchedRefreshToken = row;
        break;
      }
    }

    if(!matchedRefreshToken) {
      res.status(404).json({
        success: false,
        error: "Refresh token not found or is invalid"
      });
      return;
    }

    if(matchedRefreshToken?.is_revoked) {
      res.status(401).json({
        success: false,
        error: "Refresh token is revoked"
      });
      return;
    }

    if(new Date(matchedRefreshToken?.expires_at) < new Date()) {
      res.status(401).json({
        success: false,
        error: "Refresh token is expired!"
      });
      return;
    }

    // sign new access and refresh token to user
    const newAccessToken = await signAccessToken({ id: payload?.id, email: payload?.email });
    const newRefreshToken = await signRefreshToken({ id: payload?.id, email: payload?.email });

    // hash the new refresh token
    const newHashedRefreshToken = await hashItem(newRefreshToken);

    const id = uuid();

    // update the database 
    await db.query<ResultSetHeader>("INSERT INTO refresh_tokens (id, user_id, token_hash, expires_at) VALUES (?, ?, ?, ?)", [id, payload?.id, newHashedRefreshToken, expiresAt]);

    // revoke the old refresh token
    await db.query<ResultSetHeader>("UPDATE refresh_tokens SET is_revoked = 1 WHERE id = ?", [matchedRefreshToken?.id]);

    // store new refresh token in httpOnly cookies
    res.cookie("refreshToken", newRefreshToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production" ? true : false,
      sameSite: "none",
      path: "/",
      maxAge: 7 * 24 * 60 * 60 * 1000,
    })

    res.status(200).json({
      success: true,
      accessToken: newAccessToken
    });
    return;

  } catch(err: any) {
      console.error("Failed to refresh: ", err);
      // clear the refresh token from the browser cookie
      res.clearCookie("refreshToken", {
        httpOnly: true,
        sameSite: process.env.NODE_ENV === "production" ? "none" : "lax",
        path: "/user/refresh",
      });

      if (err.name === "TokenExpiredError") {
        res.status(401).json({
          success: false,
          error: "Refresh token expired",
        });
        return;
      } else {
        res.status(401).json({
          success: false,
          error: "Invalid refresh token",
        });
        return;
      }
  }
}

// controller to log out user
export const logoutUser = async (req: Request, res: Response): Promise<void> => {
  const { refreshToken }: { refreshToken?: string } = req.cookies;

  if(!refreshToken) {
    res.status(400).json({
      success: false,
      error: "Refresh token required! User might be logged out already"
    })
    return;
  }

  try {
    let payload;

    // try to verify refresh token if it is not expired
    try {
      payload = await verifyRefreshToken(refreshToken);
    } catch(err: unknown) {
      // incase refresh token is expired, decode it manually be removed from database
      const base64Payload = refreshToken.split(".")[1];
      payload = JSON.parse(Buffer.from(base64Payload as string, "base64").toString());

    } finally {
        const userId = payload?.id;

        // make a query to get the exact refresh token to revoke
        const [rows] = await db.query<RowDataPacket[]>("SELECT * FROM refresh_tokens WHERE user_id = ?", [userId]);

        let matchedRefreshToken: RowDataPacket | null = null;

        for(const row of rows) {
          const isMatch = await compareHashedItem(refreshToken, row?.token_hash);
          if(isMatch) {
            matchedRefreshToken = row;
            break;
          }
        }

        // set the revoke the refresh token in the database
        await db.query<ResultSetHeader>("UPDATE refresh_tokens SET is_revoked = 1 WHERE id = ? AND user_id = ?", [matchedRefreshToken?.id, matchedRefreshToken?.user_id]);

        // clear the refresh token from the coolie
        res.clearCookie("refreshToken", {
          httpOnly: true,
          secure: process.env.NODE_ENV === "production" ? true : false,
          sameSite: process.env.NODE_ENV === "production" ? "none" : "lax",
          path: "/",
        });

        res.status(200).json({
          success: true,
          message: "User logged out successfully!✅"
        });
        return;
    }

  } catch(err: unknown) {
      console.error("Failed to log out user: ", err);
      res.status(500).json({
        success: false,
        error: "Failed to log out user. Internal server error!"
      })
  } 
} 

