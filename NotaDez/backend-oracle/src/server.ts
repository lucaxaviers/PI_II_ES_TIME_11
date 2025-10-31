import http from "http";
import fs from "fs";
import path from "path";
import { handleRequest } from "./routes";

const server = http.createServer((req, res) => {
  // Se for rota da API (começa com /api), manda pro routes.ts
  if (req.url?.startsWith("/api")) {
    handleRequest(req, res);
    return;
  }

  // Garante que a URL sempre tenha valor
  const url = req.url || "/";

  // Define a pasta base do frontend
  const basePath = path.join(__dirname, "../../frontend");

  // Se a pessoa acessa "/", abre o login.html
  const filePath =
    url === "/" ? path.join(basePath, "login.html") : path.join(basePath, url);

  // Define o tipo de arquivo
  let contentType = "text/html";
  const ext = path.extname(filePath);
  if (ext === ".css") contentType = "text/css";
  else if (ext === ".js") contentType = "application/javascript";
  else if (ext === ".json") contentType = "application/json";
  else if (ext === ".png") contentType = "image/png";
  else if (ext === ".jpg" || ext === ".jpeg") contentType = "image/jpeg";

  // Lê e envia o arquivo
  fs.readFile(filePath, (err, content) => {
    if (err) {
      res.writeHead(404, { "Content-Type": "text/plain; charset=utf-8" });
      res.end("Página não encontrada 😕");
    } else {
      res.writeHead(200, { "Content-Type": contentType + "; charset=utf-8" });
      res.end(content);
    }
  });
});

server.listen(3000, () =>
  console.log("✅ Servidor rodando em http://localhost:3000")
);
