import bcrypt from "bcrypt";

const SALT_ROUNDS = 10;

// function to hash items (password, tokens, etc)
export async function hashItem(item: string): Promise<string> {
  return await bcrypt.hash(item, SALT_ROUNDS)
}

export async function compareHashedItem(item: string, hashedItem: string): Promise<boolean> {
  return await bcrypt.compare(item, hashedItem)
}