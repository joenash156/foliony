import crypto from "crypto";

export function generateSlugSuffix(length = 4): string {
  return crypto.randomBytes(length)
    .toString("hex")
    .slice(0, length);
}
