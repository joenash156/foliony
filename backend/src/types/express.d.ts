import { TokenPayload } from "../utils/jwt";
// import { Request } from "express";

declare global {
  namespace Express {
    interface Request {
      user?: TokenPayload;
    }
  }
}

// declare module "express-serve-static-core" {
//   interface Request {
//     user?: {
//       id: string;
//       email: string;
//     };
//   }
// }


export {};
