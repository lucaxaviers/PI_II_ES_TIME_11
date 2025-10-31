import http from "http";
import fs from "fs";
import path from "path";
import { handleRequest } from "./routes"; // importa as rotas

const server = http.createServer((req, res) => {
  // Se for rota da API (todas as rotas do backend)
  const apiPaths = [
    "/login",
    "/registrar",
    "/instituicao/",
    "/turma/",
    "/aluno/",
    "/nota/",
  ];

  // verifica se é uma rota de API
  if (apiPaths.some((p) => req.url?.startsWith(p))) {
    handleRequest(req, res);
    return;
  }

  // --------------------------------------------
  // SERVE OS ARQUIVOS DO FRONTEND (HTML, CSS, etc)
  // --------------------------------------------

  const url = req.url === "/" ? "/login.html" : req.url || "/";
  const basePath = path.join(__dirname, "../../frontend");
  const filePath = path.join(basePath, url);

  // define tipo de conteúdo
  let contentType = "text/html";
  const ext = path.extname(filePath).toLowerCase();

  switch (ext) {
    case ".css":
      contentType = "text/css";
      break;
    case ".js":
      contentType = "application/javascript";
      break;
    case ".json":
      contentType = "application/json";
      break;
    case ".png":
      contentType = "image/png";
      break;
    case ".jpg":
    case ".jpeg":
      contentType = "image/jpeg";
      break;
    default:
      contentType = "text/html";
  }

  // lê e envia arquivo
  fs.readFile(filePath, (err, content) => {
    if (err) {
      res.writeHead(404, { "Content-Type": "text/plain; charset=utf-8" });
      res.end("Página não encontrada 😕");
    } else {
      res.writeHead(200, { "Content-Type": `${contentType}; charset=utf-8` });
      res.end(content);
    }
  });
});

// inicia o servidor
server.listen(3000, () => {
  console.log("✅ Servidor rodando em http://localhost:3000");
});
