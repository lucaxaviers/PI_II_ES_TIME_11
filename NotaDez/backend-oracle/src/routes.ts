import { IncomingMessage, ServerResponse } from "http";
import oracledb from "oracledb";
import { connectDB } from "./database";

export async function handleRequest(req: IncomingMessage, res: ServerResponse) {
  const { method, url } = req;

  // ============================================================
  //  LOGIN (POST /api/login)
  // ============================================================
  if (method === "POST" && url === "/api/login") {
    let body = "";
    req.on("data", chunk => (body += chunk));
    req.on("end", async () => {
      const dados = JSON.parse(body);
      console.log("📩 Login recebido:", dados);

      try {
        const conn = await connectDB(); // ✅ nome corrigido
        const result = await conn.execute(
          `SELECT ID_DOCENTE, NOME, EMAIL
           FROM DOCENTE
           WHERE EMAIL = :email AND SENHA = :senha`,
          { email: dados.email, senha: dados.senha },
          { outFormat: oracledb.OUT_FORMAT_OBJECT }
        );

        await conn.close();

        if (result.rows && result.rows.length > 0) {
          const usuario: any = result.rows[0];
          res.writeHead(200, { "Content-Type": "application/json" });
          res.end(JSON.stringify({
            sucesso: true,
            mensagem: "Login realizado com sucesso!",
            id_docente: usuario.ID_DOCENTE,
            nome: usuario.NOME
          }));
        } else {
          res.writeHead(401, { "Content-Type": "application/json" });
          res.end(JSON.stringify({
            sucesso: false,
            erro: "Email ou senha incorretos."
          }));
        }
      } catch (error) {
        console.error("❌ Erro no login:", error);
        res.writeHead(500, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ sucesso: false, erro: "Erro no servidor." }));
      }
    });
    return;
  }

  // ============================================================
  //  ROTA PADRÃO (404)
  // ============================================================
  res.writeHead(404, { "Content-Type": "application/json" });
  res.end(JSON.stringify({ erro: "Rota não encontrada." }));
}
