import { IncomingMessage, ServerResponse } from "http";
import oracledb from "oracledb";
import { connectDB } from "./database";

export async function handleRequest(req: IncomingMessage, res: ServerResponse) {
  const { method, url } = req;

  // 🔹 CORS
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type");
  if (method === "OPTIONS") {
    res.writeHead(204);
    res.end();
    return;
  }

  // Lê corpo JSON
  async function readBody(): Promise<any> {
    return new Promise((resolve) => {
      let body = "";
      req.on("data", (chunk) => (body += chunk));
      req.on("end", () => {
        try {
          resolve(body ? JSON.parse(body) : {});
        } catch {
          resolve({});
        }
      });
    });
  }

  try {
    // ============================================================
    // 1️⃣ CADASTRO (POST /registrar)
    // ============================================================
    if (method === "POST" && url === "/registrar") {
      const dados = await readBody();
      const conn = await connectDB();

      // Evita duplicar e-mail
      const check = await conn.execute(
        `SELECT COUNT(*) AS TOTAL FROM DOCENTE WHERE EMAIL = :email`,
        { email: dados.email },
        { outFormat: oracledb.OUT_FORMAT_OBJECT }
      );
      const jaExiste = check.rows && (check.rows[0] as any).TOTAL > 0;
      if (jaExiste) {
        await conn.close();
        res.writeHead(409, { "Content-Type": "application/json" });
        res.end(
          JSON.stringify({ sucesso: false, erro: "E-mail já cadastrado." })
        );
        return;
      }

      await conn.execute(
        `INSERT INTO DOCENTE (NOME, TELEFONE, EMAIL, SENHA)
         VALUES (:nome, :telefone, :email, :senha)`,
        {
          nome: dados.nome,
          telefone: dados.telefone,
          email: dados.email,
          senha: dados.senha,
        },
        { autoCommit: true }
      );

      await conn.close();
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(
        JSON.stringify({
          sucesso: true,
          mensagem: "Conta criada com sucesso!",
        })
      );
      return;
    }

    // ============================================================
    // 2️⃣ LOGIN (POST /login)
    // ============================================================
    if (method === "POST" && (url === "/login.html" || url === "/api/login.html")) {
      const dados = await readBody();
      const conn = await connectDB();
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
        return sendJSON(res, {
          sucesso: true,
          mensagem: "Login realizado com sucesso!",
          id_docente: usuario.ID_DOCENTE,
          nome: usuario.NOME,
        });
      } else {
        return sendJSON(res, { sucesso: false, erro: "Credenciais inválidas." }, 401);
      }
    }

    // ============================================================
    // 3️⃣ INSTITUIÇÕES
    // ============================================================
    if (method === "POST" && url === "/instituicao/criar") {
      const dados = await readBody();
      const conn = await connectDB();
      await conn.execute(
        `INSERT INTO INSTITUICAO (NOME, ID_DOCENTE)
         VALUES (:nome, :id_docente)`,
        { nome: dados.nome, id_docente: dados.id_docente },
        { autoCommit: true }
      );
      await conn.close();
      return sendJSON(res, { ok: true });
    }

    if (method === "GET" && url?.startsWith("/instituicao/listar")) {
      const params = new URLSearchParams(url.split("?")[1]);
      const id_docente = params.get("id_docente");
      const conn = await connectDB();
      const result = await conn.execute(
        `SELECT ID_INSTITUICAO, NOME FROM INSTITUICAO WHERE ID_DOCENTE = :id_docente`,
        { id_docente },
        { outFormat: oracledb.OUT_FORMAT_OBJECT }
      );
      await conn.close();
      return sendJSON(res, result.rows || []);
    }

    // ============================================================
    // 4️⃣ TURMAS
    // ============================================================
    if (method === "POST" && url === "/turma/criar") {
      const dados = await readBody();
      const conn = await connectDB();
      await conn.execute(
        `INSERT INTO TURMA (NOME, CODIGO, ID_DISCIPLINA)
         VALUES (:nome, :codigo, :id_disciplina)`,
        {
          nome: dados.nome,
          codigo: dados.codigo,
          id_disciplina: dados.id_disciplina,
        },
        { autoCommit: true }
      );
      await conn.close();
      return sendJSON(res, { ok: true });
    }

    if (method === "GET" && url?.startsWith("/turma/listar")) {
      const params = new URLSearchParams(url.split("?")[1]);
      const id_disciplina = params.get("id_disciplina");
      const conn = await connectDB();
      const result = await conn.execute(
        `SELECT ID_TURMA, NOME, CODIGO FROM TURMA WHERE ID_DISCIPLINA = :id_disciplina`,
        { id_disciplina },
        { outFormat: oracledb.OUT_FORMAT_OBJECT }
      );
      await conn.close();
      return sendJSON(res, result.rows || []);
    }

    // ============================================================
    // 5️⃣ ALUNOS
    // ============================================================
    if (method === "POST" && url === "/aluno/importar") {
      const dados = await readBody();
      const conn = await connectDB();

      const linhas = dados.csv
        .split("\n")
        .map((l: string) => l.trim())
        .filter((l: string) => l && !l.startsWith("matricula"));

      for (const linha of linhas) {
        const [matricula, nome] = linha.split(",");
        await conn.execute(
          `INSERT INTO ALUNO (MATRICULA, NOME, ID_TURMA)
           VALUES (:matricula, :nome, :id_turma)`,
          { matricula, nome, id_turma: dados.id_turma },
          { autoCommit: true }
        );
      }

      await conn.close();
      return sendJSON(res, { ok: true });
    }

    if (method === "GET" && url?.startsWith("/aluno/listar")) {
      const params = new URLSearchParams(url.split("?")[1]);
      const id_turma = params.get("id_turma");
      const conn = await connectDB();
      const result = await conn.execute(
        `SELECT ID_ALUNO, MATRICULA, NOME FROM ALUNO WHERE ID_TURMA = :id_turma`,
        { id_turma },
        { outFormat: oracledb.OUT_FORMAT_OBJECT }
      );
      await conn.close();
      return sendJSON(res, result.rows || []);
    }

    // ============================================================
    // 6️⃣ NOTAS
    // ============================================================
    if (method === "POST" && url === "/nota/salvar") {
      const dados = await readBody();
      const conn = await connectDB();
      await conn.execute(
        `MERGE INTO NOTA n
         USING DUAL ON (n.ID_ALUNO = :id_aluno AND n.ID_COMPONENTE = :id_componente)
         WHEN MATCHED THEN UPDATE SET n.VALOR = :valor
         WHEN NOT MATCHED THEN INSERT (ID_ALUNO, ID_COMPONENTE, VALOR)
           VALUES (:id_aluno, :id_componente, :valor)`,
        {
          id_aluno: dados.id_aluno,
          id_componente: dados.id_componente,
          valor: dados.valor,
        },
        { autoCommit: true }
      );
      await conn.close();
      return sendJSON(res, { ok: true });
    }

    if (method === "GET" && url?.startsWith("/nota/ver")) {
      const params = new URLSearchParams(url.split("?")[1]);
      const id_turma = params.get("id_turma");
      const conn = await connectDB();
      const result = await conn.execute(
        `SELECT A.MATRICULA, A.NOME, ROUND(AVG(N.VALOR), 2) AS MEDIA_FINAL
         FROM ALUNO A
         JOIN NOTA N ON A.ID_ALUNO = N.ID_ALUNO
         WHERE A.ID_TURMA = :id_turma
         GROUP BY A.MATRICULA, A.NOME
         ORDER BY A.NOME`,
        { id_turma },
        { outFormat: oracledb.OUT_FORMAT_OBJECT }
      );
      await conn.close();
      return sendJSON(res, result.rows || []);
    }

    // ============================================================
    // 7️⃣ PADRÃO (404)
    // ============================================================
    sendJSON(res, { erro: "Rota não encontrada." }, 404);
  } catch (error) {
    console.error("❌ Erro geral:", error);
    sendJSON(res, { erro: "Erro interno no servidor." }, 500);
  }
}

// Utilitário de resposta JSON
function sendJSON(res: ServerResponse, data: any, status = 200) {
  res.writeHead(status, { "Content-Type": "application/json; charset=utf-8" });
  res.end(JSON.stringify(data));
}
