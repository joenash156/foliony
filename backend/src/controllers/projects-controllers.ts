import db from "../configs/database";
import { Request, Response } from "express"
import { v4 as uuid } from "uuid";
import { ResultSetHeader, RowDataPacket } from "mysql2";

interface InsertProjectRequestBody {
  title: string,
  description: string,
  techStacks: string[],
  githubURL: string,
  liveURL: string,
  image: string,
  isVisible: number 
}


export const insertProject = async (req: Request, res: Response): Promise<void> => {

  const userId: string = req.user?.id;

  if(!userId) {
    res.status(401).json({
      success: false,
      error: "User must be authorized to insert a project"
    });
    return;
  }

  const { title, description, techStacks,  githubURL, liveURL, image, isVisible }: InsertProjectRequestBody = req.body;

  const validateTechStacks = (stackArr: unknown): boolean =>  {
    // check if array exists
    if(!Array.isArray(stackArr)) {
      return false;
    }

    // check if it is not empty
    if(stackArr.length === 0) {
      return false;
    }

    // check if every item is a non-empty string
    for(const stack of stackArr) {
      if(typeof stack !== "string" || stack.trim().length === 0) {
        return false;
      }
    }

    return true;
  }

  if(!title || !description || !validateTechStacks(techStacks)) {
    res.status(400).json({
      success: false,
      error: "Invalid project data provided"
    });
    return;
  }

  // normalize inputs for tech stacks
  

}