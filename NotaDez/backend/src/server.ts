import http from 'http';
import { 
    handleRegister, 
    handleLogin, 
    handleForgotPassword,
    handleGetInstituicoes,
    handleCreateInstituicao,
    handleUpdateInstituicao,
    handleDeleteInstituicao
} from './routes';
import { testConnection } from './db';
import dotenv from 'dotenv';

// Carrega variáveis de ambiente
dotenv.config();

const PORT = process.env.PORT || 3000;

/**
 * Cria e configura o servidor HTTP
 */
const server = http.createServer(async (req: http.IncomingMessage, res: http.ServerResponse) => {
    // Configura CORS básico
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');

    // Trata requisições OPTIONS (preflight)
    if (req.method === 'OPTIONS') {
        res.writeHead(200);
        res.end();
        return;
    }

    const url = req.url || '';
    const method = req.method;

    // Roteamento manual das rotas
    // Rotas de autenticação
    if (method === 'POST' && url === '/register') {
        await handleRegister(req, res);
    } else if (method === 'POST' && url === '/login') {
        await handleLogin(req, res);
    } else if (method === 'POST' && url === '/forgot-password') {
        await handleForgotPassword(req, res);
    } 
    // Rotas de instituições
    else if (method === 'GET' && url === '/instituicoes') {
        await handleGetInstituicoes(req, res);
    } else if (method === 'POST' && url === '/instituicoes') {
        await handleCreateInstituicao(req, res);
    } else if (method === 'PUT' && url.startsWith('/instituicoes/')) {
        const id = parseInt(url.split('/')[2]);
        if (isNaN(id)) {
            res.writeHead(400, { 'Content-Type': 'application/json; charset=utf-8' });
            res.end(JSON.stringify({
                success: false,
                message: 'ID inválido'
            }));
        } else {
            await handleUpdateInstituicao(req, res, id);
        }
    } else if (method === 'DELETE' && url.startsWith('/instituicoes/')) {
        const id = parseInt(url.split('/')[2]);
        if (isNaN(id)) {
            res.writeHead(400, { 'Content-Type': 'application/json; charset=utf-8' });
            res.end(JSON.stringify({
                success: false,
                message: 'ID inválido'
            }));
        } else {
            await handleDeleteInstituicao(req, res, id);
        }
    } else {
        // Rota não encontrada
        res.writeHead(404, { 'Content-Type': 'application/json; charset=utf-8' });
        res.end(JSON.stringify({
            success: false,
            message: 'Rota não encontrada'
        }));
    }
});

/**
 * Inicia o servidor
 */
async function startServer() {
    try {
        // Testa a conexão com o banco antes de iniciar
        await testConnection();

        server.listen(PORT, () => {
            console.log(`🚀 Servidor rodando na porta ${PORT}`);
            console.log(`📡 Endpoints disponíveis:`);
            console.log(`   Autenticação:`);
            console.log(`     POST http://localhost:${PORT}/register`);
            console.log(`     POST http://localhost:${PORT}/login`);
            console.log(`     POST http://localhost:${PORT}/forgot-password`);
            console.log(`   Instituições:`);
            console.log(`     GET    http://localhost:${PORT}/instituicoes`);
            console.log(`     POST   http://localhost:${PORT}/instituicoes`);
            console.log(`     PUT    http://localhost:${PORT}/instituicoes/:id`);
            console.log(`     DELETE http://localhost:${PORT}/instituicoes/:id`);
        });
    } catch (error) {
        console.error('❌ Erro ao iniciar servidor:', error);
        process.exit(1);
    }
}

// Inicia o servidor
startServer();

