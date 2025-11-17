/* Autores do arquivo: Todos os integrantes */

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
    handleDeleteAluno,
    handleGetComponentes,
    handleCreateComponente,
    handleUpdateComponente,
    handleDeleteComponente,
    handleGetNotas,
    handleBulkNotas
} from './routes';
import { testConnection } from './db';
import dotenv from 'dotenv';

dotenv.config();

const PORT = process.env.PORT || 3000;

const server = http.createServer(async (req: http.IncomingMessage, res: http.ServerResponse) => {
    
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');

    if (req.method === 'OPTIONS') {
        res.writeHead(200);
        res.end();
        return;
    }

    let url = (req.url || '').trim();
    const method = req.method;

    const urlPath = url.split('?')[0].trim();

    console.log(`[${new Date().toISOString()}] ${method} ${urlPath}${url !== urlPath ? ` (query: ${url.split('?')[1]})` : ''}`);

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
        
        console.log('  → Rota: GET /cursos');
        await handleGetCursos(req, res);
    } else if (method === 'POST' && urlPath === '/cursos') {
        console.log('  → Rota: POST /cursos');
        await handleCreateCurso(req, res);
    }
    
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
        
        console.log('  → Rota: GET /disciplinas');
        await handleGetDisciplinas(req, res);
    } else if (method === 'POST' && urlPath === '/disciplinas') {
        console.log('  → Rota: POST /disciplinas');
        await handleCreateDisciplina(req, res);
    }
    
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
        
        console.log('  → Rota: GET /turmas');
        await handleGetTurmas(req, res);
    } else if (method === 'POST' && urlPath === '/turmas') {
        console.log('  → Rota: POST /turmas');
        await handleCreateTurma(req, res);
    }
    
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
        
        console.log('  → Rota: GET /alunos');
        await handleGetAlunos(req, res);
    } else if (method === 'POST' && urlPath === '/alunos') {
        console.log('  → Rota: POST /alunos');
        await handleCreateAluno(req, res);
    }
    
    else if (method === 'PUT' && urlPath.startsWith('/componentes/')) {
        const urlParts = urlPath.split('/');
        const id = parseInt(urlParts[2]);
        if (isNaN(id)) {
            console.log(`  → Erro: ID inválido em PUT /componentes/${urlParts[2]}`);
            res.writeHead(400, { 'Content-Type': 'application/json; charset=utf-8' });
            res.end(JSON.stringify({
                success: false,
                message: 'ID inválido'
            }));
        } else {
            console.log(`  → Rota: PUT /componentes/${id}`);
            await handleUpdateComponente(req, res, id);
        }
    } else if (method === 'DELETE' && urlPath.startsWith('/componentes/')) {
        const urlParts = urlPath.split('/');
        const id = parseInt(urlParts[2]);
        if (isNaN(id)) {
            console.log(`  → Erro: ID inválido em DELETE /componentes/${urlParts[2]}`);
            res.writeHead(400, { 'Content-Type': 'application/json; charset=utf-8' });
            res.end(JSON.stringify({
                success: false,
                message: 'ID inválido'
            }));
        } else {
            console.log(`  → Rota: DELETE /componentes/${id}`);
            await handleDeleteComponente(req, res, id);
        }
    } else if (method === 'GET' && urlPath === '/componentes') {
        
        console.log('  → Rota: GET /componentes');
        await handleGetComponentes(req, res);
    } else if (method === 'POST' && urlPath === '/componentes') {
        console.log('  → Rota: POST /componentes');
        await handleCreateComponente(req, res);
    }
    
    else if (method === 'GET' && urlPath === '/notas') {
        
        console.log('  → Rota: GET /notas');
        await handleGetNotas(req, res);
    } else if (method === 'POST' && urlPath === '/notas/bulk') {
        console.log('  → Rota: POST /notas/bulk');
        await handleBulkNotas(req, res);
    } else {
        
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

async function startServer() {
    try {
        
        await testConnection();

        server.listen(PORT, () => {
            console.log('\n✅ Conexão com MySQL estabelecida com sucesso!');
            console.log(`\n🚀 Servidor rodando na porta ${PORT}`);
            console.log('\n📡 Endpoints disponíveis:');
            console.log('\n   Autenticação:');
            console.log('     POST http://localhost:3000/register');
            console.log('     POST http://localhost:3000/login');
            console.log('     POST http://localhost:3000/forgot-password');
            console.log('\n   Instituições:');
            console.log('     GET    http://localhost:3000/instituicoes');
            console.log('     POST   http://localhost:3000/instituicoes');
            console.log('     PUT    http://localhost:3000/instituicoes/:id');
            console.log('     DELETE http://localhost:3000/instituicoes/:id');
            console.log('\n   Cursos:');
            console.log('     GET    http://localhost:3000/cursos?instituicaoId=X');
            console.log('     POST   http://localhost:3000/cursos');
            console.log('     PUT    http://localhost:3000/cursos/:id');
            console.log('     DELETE http://localhost:3000/cursos/:id');
            console.log('\n   Disciplinas:');
            console.log('     GET    http://localhost:3000/disciplinas?cursoId=X');
            console.log('     POST   http://localhost:3000/disciplinas');
            console.log('     PUT    http://localhost:3000/disciplinas/:id');
            console.log('     DELETE http://localhost:3000/disciplinas/:id');
            console.log('\n   Turmas:');
            console.log('     GET    http://localhost:3000/turmas?disciplinaId=X');
            console.log('     POST   http://localhost:3000/turmas');
            console.log('     PUT    http://localhost:3000/turmas/:id');
            console.log('     DELETE http://localhost:3000/turmas/:id');
            console.log('\n   Alunos:');
            console.log('     GET    http://localhost:3000/alunos?turmaId=X');
            console.log('     POST   http://localhost:3000/alunos');
            console.log('     PUT    http://localhost:3000/alunos/:id');
            console.log('     DELETE http://localhost:3000/alunos/:id');
            console.log('\n   Componentes de Nota:');
            console.log('     GET    http://localhost:3000/componentes?disciplinaId=X');
            console.log('     POST   http://localhost:3000/componentes');
            console.log('     PUT    http://localhost:3000/componentes/:id');
            console.log('     DELETE http://localhost:3000/componentes/:id');
            console.log('\n   Notas:');
            console.log('     GET    http://localhost:3000/notas?turmaId=X');
            console.log('     POST   http://localhost:3000/notas/bulk');
            console.log('');
        });
    } catch (error: any) {
        console.error('❌ Erro ao iniciar servidor:', error.message);
        process.exit(1);
    }
}

startServer();

