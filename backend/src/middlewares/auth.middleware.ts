import { verifyAccessToken } from "../utils/jwt";
import db from "../configs/database";
import { Response, Request, NextFunction } from "express";
import { RowDataPacket } from "mysql2";

export async function requireAuth(req:Request, res: Response, next: NextFunction): Promise<void> {
  const authHeader = req.headers.authorization?.trim();
  let token = "";
  
  // check if authHeader exists to split
  if(authHeader) {
    // split into two parts to get the bearer and actual token
    const parts = authHeader.split(" ");
    // check if the length of the parts array is two and the first element is bearer
    if(parts.length === 2 && parts[0]?.toLowerCase() === "bearer") {
      token = parts[1] as string;
    }
  }

  if(!token) {
    res.status(401).json({
      success: false,
      error: "Missing authorization token",
    });

    return
  }

  try {
    const payload = await verifyAccessToken(token)

    const [user] = await db.query<RowDataPacket[]>("SELECT id, email FROM users WHERE id = ?", [payload.id]);
    if(user.length === 0) {
        res.status(401).json({
        success: false,
        error: "User does not exist, account might have been deleted!"
      });

      return
    }

    // form a req user for authorization in future requests after login
    req.user = {
      id: payload.id,
      email: payload.email
    }

    next();

  } catch(err: any | unknown) {
    if(err.name === "TokenExpiredError") {
      res.status(401).json({
        success: false,
        error: "Access token is expired" 
      })
      return
    }
    
    res.status(401).json({
      success: false,
      error: "Invalid access token"
    })
    return
    }
}