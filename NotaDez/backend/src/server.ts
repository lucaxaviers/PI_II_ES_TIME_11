import http from 'http';
import { handleRegister, handleLogin, handleForgotPassword } from './routes';
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
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
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
    if (method === 'POST' && url === '/register') {
        await handleRegister(req, res);
    } else if (method === 'POST' && url === '/login') {
        await handleLogin(req, res);
    } else if (method === 'POST' && url === '/forgot-password') {
        await handleForgotPassword(req, res);
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
            console.log(`   POST http://localhost:${PORT}/register`);
            console.log(`   POST http://localhost:${PORT}/login`);
            console.log(`   POST http://localhost:${PORT}/forgot-password`);
        });
    } catch (error) {
        console.error('❌ Erro ao iniciar servidor:', error);
        process.exit(1);
    }
}

// Inicia o servidor
startServer();

