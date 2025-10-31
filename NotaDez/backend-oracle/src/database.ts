// backend/src/database.ts
import oracledb from "oracledb";

oracledb.outFormat = oracledb.OUT_FORMAT_OBJECT;

export async function connectDB() {
  try {
    const connection = await oracledb.getConnection({
      user: "system",             // o usuário que você criou
      password: "admin",          // senha que definiu
      connectString: "localhost:1521/XEPDB1", // padrão do Oracle 21c XE
    });

    console.log("✅ Conectado ao banco Oracle com sucesso!");
    return connection;
  } catch (err) {
    console.error("❌ Erro ao conectar no Oracle:", err);
    throw err;
  }
}
