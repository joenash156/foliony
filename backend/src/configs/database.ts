import mysql from "mysql2/promise";
import dotenv from "dotenv";

dotenv.config();


const db = mysql.createPool({
  host: process.env.DB_HOST as string,
  user: process.env.DB_USER as string,
  password: process.env.DB_PASSWORD as string,
  database: process.env.DB_NAME as string,
  port: Number(process.env.DB_PORT),
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0,
})



// test the database connection
db.getConnection().then((connection) => {
  console.log("Connected to database successfully!✅");
  connection.release();
}).catch((err) => {
  console.error(`Connection to database failed!: ${err.stack}`)
})

export default db;