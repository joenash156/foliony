import jwt, { JwtPayload } from "jsonwebtoken";

interface TokenPayload {
  id: string;
  email: string;
}

const ACCESS_TOKEN_SECRET_KEY = process.env.JWT_ACCESS_TOKEN_SECRET as string;
const REFRESH_TOKEN_SECRET_KEY = process.env.JWT_REFRESH_TOKEN_SECRET as string;

async function signAccessToken(payload: TokenPayload): Promise<string> {
  return jwt.sign(payload, ACCESS_TOKEN_SECRET_KEY, { expiresIn: "15m" });
}

async function signRefreshToken(payload: TokenPayload): Promise<string> {
  return jwt.sign(payload, REFRESH_TOKEN_SECRET_KEY, { expiresIn: "7d" });
}

async function verifyAccessToken(token: string): Promise<TokenPayload> {
  const decoded = jwt.verify(token, ACCESS_TOKEN_SECRET_KEY) as JwtPayload;
  return decoded as TokenPayload;
}

async function verifyRefreshToken(token: string): Promise<TokenPayload> {
  const decoded = jwt.verify(token, REFRESH_TOKEN_SECRET_KEY) as JwtPayload;
  return decoded as TokenPayload;
}

export {
  signAccessToken,
  signRefreshToken,
  verifyAccessToken,
  verifyRefreshToken
};




// import jwt, { JwtPayload } from "jsonwebtoken";

// interface TokenPayload {
//   id: string;
//   email: string;
// }

// const ACCESS_TOKEN_SECRET_KEY = process.env.JWT_ACCESS_TOKEN_SECRET as string;
// const REFRESH_TOKEN_SECRET_KEY = process.env.JWT_REFRESH_TOKEN_SECRET as string;

// function signAccessToken(payload: TokenPayload | JwtPayload): string {
//   return jwt.sign(payload, ACCESS_TOKEN_SECRET_KEY, { expiresIn: "15m" });
// }

// function signRefreshToken(payload: TokenPayload | JwtPayload): string {
//   return jwt.sign(payload, REFRESH_TOKEN_SECRET_KEY, { expiresIn: "7d" })
// }

// function verifyAccessToken(token: string ): TokenPayload {
//   return jwt.verify(token, ACCESS_TOKEN_SECRET_KEY);
// }

// function verifyRefreshToken(token: string): string | JwtPayload {
//   return jwt.verify(token, REFRESH_TOKEN_SECRET_KEY);
// }

// export { signAccessToken, signRefreshToken, verifyAccessToken, verifyRefreshToken }