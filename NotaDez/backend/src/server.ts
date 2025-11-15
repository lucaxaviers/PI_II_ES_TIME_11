import http from 'http';
import { 
    handleRegister, 
    handleLogin, 
    handleForgotPassword,
    handleGetInstituicoes,
    handleCreateInstituicao,
    handleUpdateInstituicao,
    handleDeleteInstituicao,
    handleGetCursos,
    handleCreateCurso,
    handleUpdateCurso,
    handleDeleteCurso,
    handleGetDisciplinas,
    handleCreateDisciplina,
    handleUpdateDisciplina,
    handleDeleteDisciplina,
    handleGetTurmas,
    handleCreateTurma,
    handleUpdateTurma,
    handleDeleteTurma,
    handleGetAlunos,
    handleCreateAluno,
    handleUpdateAluno,
    handleDeleteAluno
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

    let url = (req.url || '').trim();
    const method = req.method;

    // Remove query string para roteamento (mas mantém para uso nas funções)
    const urlPath = url.split('?')[0].trim();

    // Log da requisição recebida
    console.log(`[${new Date().toISOString()}] ${method} ${urlPath}${url !== urlPath ? ` (query: ${url.split('?')[1]})` : ''}`);

    // Roteamento manual das rotas
    // Rotas de autenticação
    if (method === 'POST' && urlPath === '/register') {
        console.log('  → Rota: POST /register');
        await handleRegister(req, res);
    } else if (method === 'POST' && urlPath === '/login') {
        console.log('  → Rota: POST /login');
        await handleLogin(req, res);
    } else if (method === 'POST' && urlPath === '/forgot-password') {
        console.log('  → Rota: POST /forgot-password');
        await handleForgotPassword(req, res);
    } 
    // Rotas de instituições
    else if (method === 'GET' && urlPath === '/instituicoes') {
        console.log('  → Rota: GET /instituicoes');
        await handleGetInstituicoes(req, res);
    } else if (method === 'POST' && urlPath === '/instituicoes') {
        console.log('  → Rota: POST /instituicoes');
        await handleCreateInstituicao(req, res);
    } else if (method === 'PUT' && urlPath.startsWith('/instituicoes/')) {
        const urlParts = urlPath.split('/');
        const id = parseInt(urlParts[2]);
        if (isNaN(id)) {
            console.log(`  → Erro: ID inválido em PUT /instituicoes/${urlParts[2]}`);
            res.writeHead(400, { 'Content-Type': 'application/json; charset=utf-8' });
            res.end(JSON.stringify({
                success: false,
                message: 'ID inválido'
            }));
        } else {
            console.log(`  → Rota: PUT /instituicoes/${id}`);
            await handleUpdateInstituicao(req, res, id);
        }
    } else if (method === 'DELETE' && urlPath.startsWith('/instituicoes/')) {
        const urlParts = urlPath.split('/');
        const id = parseInt(urlParts[2]);
        if (isNaN(id)) {
            console.log(`  → Erro: ID inválido em DELETE /instituicoes/${urlParts[2]}`);
            res.writeHead(400, { 'Content-Type': 'application/json; charset=utf-8' });
            res.end(JSON.stringify({
                success: false,
                message: 'ID inválido'
            }));
        } else {
            console.log(`  → Rota: DELETE /instituicoes/${id}`);
            await handleDeleteInstituicao(req, res, id);
        }
    }
    // Rotas de cursos - verificar rotas com ID primeiro
    else if (method === 'PUT' && urlPath.startsWith('/cursos/')) {
        const urlParts = urlPath.split('/');
        const id = parseInt(urlParts[2]);
        if (isNaN(id)) {
            console.log(`  → Erro: ID inválido em PUT /cursos/${urlParts[2]}`);
            res.writeHead(400, { 'Content-Type': 'application/json; charset=utf-8' });
            res.end(JSON.stringify({
                success: false,
                message: 'ID inválido'
            }));
        } else {
            console.log(`  → Rota: PUT /cursos/${id}`);
            await handleUpdateCurso(req, res, id);
        }
    } else if (method === 'DELETE' && urlPath.startsWith('/cursos/')) {
        const urlParts = urlPath.split('/');
        const id = parseInt(urlParts[2]);
        if (isNaN(id)) {
            console.log(`  → Erro: ID inválido em DELETE /cursos/${urlParts[2]}`);
            res.writeHead(400, { 'Content-Type': 'application/json; charset=utf-8' });
            res.end(JSON.stringify({
                success: false,
                message: 'ID inválido'
            }));
        } else {
            console.log(`  → Rota: DELETE /cursos/${id}`);
            await handleDeleteCurso(req, res, id);
        }
    } else if (method === 'GET' && urlPath === '/cursos') {
        // GET /cursos?instituicaoId=X
        console.log('  → Rota: GET /cursos');
        await handleGetCursos(req, res);
    } else if (method === 'POST' && urlPath === '/cursos') {
        console.log('  → Rota: POST /cursos');
        await handleCreateCurso(req, res);
    }
    // Rotas de disciplinas - verificar rotas com ID primeiro
    else if (method === 'PUT' && urlPath.startsWith('/disciplinas/')) {
        const urlParts = urlPath.split('/');
        const id = parseInt(urlParts[2]);
        if (isNaN(id)) {
            console.log(`  → Erro: ID inválido em PUT /disciplinas/${urlParts[2]}`);
            res.writeHead(400, { 'Content-Type': 'application/json; charset=utf-8' });
            res.end(JSON.stringify({
                success: false,
                message: 'ID inválido'
            }));
        } else {
            console.log(`  → Rota: PUT /disciplinas/${id}`);
            await handleUpdateDisciplina(req, res, id);
        }
    } else if (method === 'DELETE' && urlPath.startsWith('/disciplinas/')) {
        const urlParts = urlPath.split('/');
        const id = parseInt(urlParts[2]);
        if (isNaN(id)) {
            console.log(`  → Erro: ID inválido em DELETE /disciplinas/${urlParts[2]}`);
            res.writeHead(400, { 'Content-Type': 'application/json; charset=utf-8' });
            res.end(JSON.stringify({
                success: false,
                message: 'ID inválido'
            }));
        } else {
            console.log(`  → Rota: DELETE /disciplinas/${id}`);
            await handleDeleteDisciplina(req, res, id);
        }
    } else if (method === 'GET' && urlPath === '/disciplinas') {
        // GET /disciplinas?cursoId=X
        console.log('  → Rota: GET /disciplinas');
        await handleGetDisciplinas(req, res);
    } else if (method === 'POST' && urlPath === '/disciplinas') {
        console.log('  → Rota: POST /disciplinas');
        await handleCreateDisciplina(req, res);
    }
    // Rotas de turmas - verificar rotas com ID primeiro
    else if (method === 'PUT' && urlPath.startsWith('/turmas/')) {
        const urlParts = urlPath.split('/');
        const id = parseInt(urlParts[2]);
        if (isNaN(id)) {
            console.log(`  → Erro: ID inválido em PUT /turmas/${urlParts[2]}`);
            res.writeHead(400, { 'Content-Type': 'application/json; charset=utf-8' });
            res.end(JSON.stringify({
                success: false,
                message: 'ID inválido'
            }));
        } else {
            console.log(`  → Rota: PUT /turmas/${id}`);
            await handleUpdateTurma(req, res, id);
        }
    } else if (method === 'DELETE' && urlPath.startsWith('/turmas/')) {
        const urlParts = urlPath.split('/');
        const id = parseInt(urlParts[2]);
        if (isNaN(id)) {
            console.log(`  → Erro: ID inválido em DELETE /turmas/${urlParts[2]}`);
            res.writeHead(400, { 'Content-Type': 'application/json; charset=utf-8' });
            res.end(JSON.stringify({
                success: false,
                message: 'ID inválido'
            }));
        } else {
            console.log(`  → Rota: DELETE /turmas/${id}`);
            await handleDeleteTurma(req, res, id);
        }
    } else if (method === 'GET' && urlPath === '/turmas') {
        // GET /turmas?disciplinaId=X
        console.log('  → Rota: GET /turmas');
        await handleGetTurmas(req, res);
    } else if (method === 'POST' && urlPath === '/turmas') {
        console.log('  → Rota: POST /turmas');
        await handleCreateTurma(req, res);
    }
    // Rotas de alunos - verificar rotas com ID primeiro
    else if (method === 'PUT' && urlPath.startsWith('/alunos/')) {
        const urlParts = urlPath.split('/');
        const id = parseInt(urlParts[2]);
        if (isNaN(id)) {
            console.log(`  → Erro: ID inválido em PUT /alunos/${urlParts[2]}`);
            res.writeHead(400, { 'Content-Type': 'application/json; charset=utf-8' });
            res.end(JSON.stringify({
                success: false,
                message: 'ID inválido'
            }));
        } else {
            console.log(`  → Rota: PUT /alunos/${id}`);
            await handleUpdateAluno(req, res, id);
        }
    } else if (method === 'DELETE' && urlPath.startsWith('/alunos/')) {
        const urlParts = urlPath.split('/');
        const id = parseInt(urlParts[2]);
        if (isNaN(id)) {
            console.log(`  → Erro: ID inválido em DELETE /alunos/${urlParts[2]}`);
            res.writeHead(400, { 'Content-Type': 'application/json; charset=utf-8' });
            res.end(JSON.stringify({
                success: false,
                message: 'ID inválido'
            }));
        } else {
            console.log(`  → Rota: DELETE /alunos/${id}`);
            await handleDeleteAluno(req, res, id);
        }
    } else if (method === 'GET' && urlPath === '/alunos') {
        // GET /alunos?turmaId=X
        console.log('  → Rota: GET /alunos');
        await handleGetAlunos(req, res);
    } else if (method === 'POST' && urlPath === '/alunos') {
        console.log('  → Rota: POST /alunos');
        await handleCreateAluno(req, res);
    } else {
        // Rota não encontrada
        console.log(`  → [404] Rota não encontrada: ${method} ${urlPath}`);
        
        res.writeHead(404, { 'Content-Type': 'application/json; charset=utf-8' });
        res.end(JSON.stringify({
            success: false,
            message: 'Rota não encontrada',
            debug: {
                method: method,
                url: url,
                urlPath: urlPath
            }
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
            console.log('\n✅ Conexão com MySQL estabelecida com sucesso!');
            console.log(`\n🚀 Servidor rodando na porta ${PORT}`);
            console.log('\n📡 Endpoints disponíveis:');
            console.log('\n   Autenticação:');
            console.log('     POST http://localhost:' + PORT + '/register');
            console.log('     POST http://localhost:' + PORT + '/login');
            console.log('     POST http://localhost:' + PORT + '/forgot-password');
            console.log('\n   Instituições:');
            console.log('     GET    http://localhost:' + PORT + '/instituicoes');
            console.log('     POST   http://localhost:' + PORT + '/instituicoes');
            console.log('     PUT    http://localhost:' + PORT + '/instituicoes/:id');
            console.log('     DELETE http://localhost:' + PORT + '/instituicoes/:id');
            console.log('\n   Cursos:');
            console.log('     GET    http://localhost:' + PORT + '/cursos?instituicaoId=X');
            console.log('     POST   http://localhost:' + PORT + '/cursos');
            console.log('     PUT    http://localhost:' + PORT + '/cursos/:id');
            console.log('     DELETE http://localhost:' + PORT + '/cursos/:id');
            console.log('\n   Disciplinas:');
            console.log('     GET    http://localhost:' + PORT + '/disciplinas?cursoId=X');
            console.log('     POST   http://localhost:' + PORT + '/disciplinas');
            console.log('     PUT    http://localhost:' + PORT + '/disciplinas/:id');
            console.log('     DELETE http://localhost:' + PORT + '/disciplinas/:id');
            console.log('\n   Turmas:');
            console.log('     GET    http://localhost:' + PORT + '/turmas?disciplinaId=X');
            console.log('     POST   http://localhost:' + PORT + '/turmas');
            console.log('     PUT    http://localhost:' + PORT + '/turmas/:id');
            console.log('     DELETE http://localhost:' + PORT + '/turmas/:id');
            console.log('\n   Alunos:');
            console.log('     GET    http://localhost:' + PORT + '/alunos?turmaId=X');
            console.log('     POST   http://localhost:' + PORT + '/alunos');
            console.log('     PUT    http://localhost:' + PORT + '/alunos/:id');
            console.log('     DELETE http://localhost:' + PORT + '/alunos/:id');
            console.log('');
        });
    } catch (error: any) {
        console.error('❌ Erro ao iniciar servidor:', error.message);
        process.exit(1);
    }
}

// Inicia o servidor
startServer();

