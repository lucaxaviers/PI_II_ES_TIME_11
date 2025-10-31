// backend-oracle/src/test_connection.ts
import { connectDB } from "./database";

(async () => {
  const conn = await connectDB();

  const result = await conn.execute(`SELECT * FROM DOCENTE`);
  console.table(result.rows);

  await conn.close();
})();
