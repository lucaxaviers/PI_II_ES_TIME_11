import { IncomingMessage, ServerResponse } from 'http';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import { query } from './db';

// Carrega variáveis de ambiente
const JWT_SECRET = process.env.JWT_SECRET || 'secret_default_change_in_production';

/**
 * Middleware de autenticação JWT
 */
export async function authenticateToken(req: IncomingMessage): Promise<any> {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1]; // Bearer TOKEN

    if (!token) {
        return null;
    }

    try {
        const decoded = jwt.verify(token, JWT_SECRET) as any;
        return decoded;
    } catch (error) {
        return null;
    }
}

/**
 * Lê o corpo da requisição e retorna como JSON
 */
async function readBody(req: IncomingMessage): Promise<any> {
    return new Promise((resolve, reject) => {
        let body = '';
        req.on('data', (chunk: Buffer) => {
            body += chunk.toString();
        });
        req.on('end', () => {
            try {
                resolve(JSON.parse(body));
            } catch (error) {
                reject(new Error('JSON inválido'));
            }
        });
        req.on('error', reject);
    });
}

/**
 * Envia resposta JSON
 */
function sendJSON(res: ServerResponse, statusCode: number, data: any): void {
    res.writeHead(statusCode, { 'Content-Type': 'application/json; charset=utf-8' });
    res.end(JSON.stringify(data));
}

/**
 * Valida se um email é válido
 */
function isValidEmail(email: string): boolean {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return emailRegex.test(email);
}

/**
 * POST /register - Cadastro de novo docente
 */
export async function handleRegister(req: IncomingMessage, res: ServerResponse): Promise<void> {
    try {
        const body = await readBody(req);
        const { nome, email, telefone, senha } = body;

        // Validação de campos obrigatórios
        if (!nome || !email || !senha) {
            return sendJSON(res, 400, {
                success: false,
                message: 'Campos obrigatórios: nome, email e senha'
            });
        }

        // Validação de email
        if (!isValidEmail(email)) {
            return sendJSON(res, 400, {
                success: false,
                message: 'Email inválido'
            });
        }

        // Validação de senha (mínimo 6 caracteres)
        if (senha.length < 6) {
            return sendJSON(res, 400, {
                success: false,
                message: 'Senha deve ter no mínimo 6 caracteres'
            });
        }

        // Verifica se o email já existe
        const existingUser = await query(
            'SELECT ID_DOCENTE FROM DOCENTE WHERE EMAIL = ?',
            [email]
        ) as any[];

        if (existingUser.length > 0) {
            return sendJSON(res, 409, {
                success: false,
                message: 'Este email já está cadastrado'
            });
        }

        // Criptografa a senha
        const saltRounds = 10;
        const hashedPassword = await bcrypt.hash(senha, saltRounds);

        // Insere o docente no banco
        const result = await query(
            'INSERT INTO DOCENTE (NOME, EMAIL, TELEFONE, SENHA) VALUES (?, ?, ?, ?)',
            [nome, email, telefone || null, hashedPassword]
        ) as any;

        sendJSON(res, 201, {
            success: true,
            message: 'Docente cadastrado com sucesso',
            data: {
                id: result.insertId,
                nome,
                email
            }
        });

    } catch (error: any) {
        sendJSON(res, 500, {
            success: false,
            message: 'Erro interno do servidor'
        });
    }
}

/**
 * POST /login - Autenticação de docente
 */
export async function handleLogin(req: IncomingMessage, res: ServerResponse): Promise<void> {
    try {
        const body = await readBody(req);
        const { email, senha } = body;

        // Validação de campos obrigatórios
        if (!email || !senha) {
            return sendJSON(res, 400, {
                success: false,
                message: 'Email e senha são obrigatórios'
            });
        }

        // Busca o docente no banco
        const users = await query(
            'SELECT ID_DOCENTE, NOME, EMAIL, SENHA FROM DOCENTE WHERE EMAIL = ?',
            [email]
        ) as any[];

        if (users.length === 0) {
            return sendJSON(res, 401, {
                success: false,
                message: 'Email ou senha inválidos'
            });
        }

        const user = users[0];

        // Compara a senha
        const passwordMatch = await bcrypt.compare(senha, user.SENHA);

        if (!passwordMatch) {
            return sendJSON(res, 401, {
                success: false,
                message: 'Email ou senha inválidos'
            });
        }

        // Gera o token JWT
        const token = jwt.sign(
            {
                id: user.ID_DOCENTE,
                nome: user.NOME,
                email: user.EMAIL
            },
            JWT_SECRET,
            { expiresIn: '24h' }
        );

        sendJSON(res, 200, {
            success: true,
            message: 'Login realizado com sucesso',
            data: {
                token,
                user: {
                    id: user.ID_DOCENTE,
                    nome: user.NOME,
                    email: user.EMAIL
                }
            }
        });

    } catch (error: any) {
        sendJSON(res, 500, {
            success: false,
            message: 'Erro interno do servidor'
        });
    }
}

/**
 * POST /forgot-password - Solicitação de recuperação de senha
 */
export async function handleForgotPassword(req: IncomingMessage, res: ServerResponse): Promise<void> {
    try {
        const body = await readBody(req);
        const { email } = body;

        // Validação de email
        if (!email) {
            return sendJSON(res, 400, {
                success: false,
                message: 'Email é obrigatório'
            });
        }

        // Sempre retorna a mesma mensagem 
        sendJSON(res, 200, {
            success: true,
            message: 'Se este e-mail existir, enviamos um link para redefinição.'
        });

    } catch (error: any) {
        sendJSON(res, 500, {
            success: false,
            message: 'Erro interno do servidor'
        });
    }
}

/**
 * GET /instituicoes - Lista todas as instituições do docente autenticado
 */
export async function handleGetInstituicoes(req: IncomingMessage, res: ServerResponse): Promise<void> {
    try {
        // Verifica autenticação
        const user = await authenticateToken(req);
        if (!user) {
            return sendJSON(res, 401, {
                success: false,
                message: 'Token de autenticação inválido ou ausente'
            });
        }

        // Busca instituições do docente
        const instituicoes = await query(
            'SELECT ID_INSTITUICAO, NOME_INSTITUICAO, CIDADE, UF FROM INSTITUICAO WHERE ID_DOCENTE = ? ORDER BY NOME_INSTITUICAO',
            [user.id]
        ) as any[];

        sendJSON(res, 200, {
            success: true,
            data: instituicoes.map(inst => ({
                id: inst.ID_INSTITUICAO,
                nome: inst.NOME_INSTITUICAO,
                cidade: inst.CIDADE,
                uf: inst.UF
            }))
        });

    } catch (error: any) {
        sendJSON(res, 500, {
            success: false,
            message: 'Erro interno do servidor'
        });
    }
}

/**
 * POST /instituicoes - Cria uma nova instituição
 */
export async function handleCreateInstituicao(req: IncomingMessage, res: ServerResponse): Promise<void> {
    try {
        // Verifica autenticação
        const user = await authenticateToken(req);
        if (!user) {
            return sendJSON(res, 401, {
                success: false,
                message: 'Token de autenticação inválido ou ausente'
            });
        }

        const body = await readBody(req);
        const { nome, cidade, uf } = body;

        // Validação de campos obrigatórios
        if (!nome) {
            return sendJSON(res, 400, {
                success: false,
                message: 'Nome da instituição é obrigatório'
            });
        }

        // Insere a instituição no banco
        const result = await query(
            'INSERT INTO INSTITUICAO (NOME_INSTITUICAO, CIDADE, UF, ID_DOCENTE) VALUES (?, ?, ?, ?)',
            [nome, cidade || null, uf || null, user.id]
        ) as any;

        sendJSON(res, 201, {
            success: true,
            message: 'Instituição cadastrada com sucesso',
            data: {
                id: result.insertId,
                nome,
                cidade: cidade || null,
                uf: uf || null
            }
        });

    } catch (error: any) {
        sendJSON(res, 500, {
            success: false,
            message: 'Erro interno do servidor'
        });
    }
}

/**
 * PUT /instituicoes/:id - Atualiza uma instituição
 */
export async function handleUpdateInstituicao(req: IncomingMessage, res: ServerResponse, id: number): Promise<void> {
    try {
        // Verifica autenticação
        const user = await authenticateToken(req);
        if (!user) {
            return sendJSON(res, 401, {
                success: false,
                message: 'Token de autenticação inválido ou ausente'
            });
        }

        const body = await readBody(req);
        const { nome, cidade, uf } = body;

        // Validação de campos obrigatórios
        if (!nome) {
            return sendJSON(res, 400, {
                success: false,
                message: 'Nome da instituição é obrigatório'
            });
        }

        // Verifica se a instituição pertence ao docente
        const instituicoes = await query(
            'SELECT ID_INSTITUICAO FROM INSTITUICAO WHERE ID_INSTITUICAO = ? AND ID_DOCENTE = ?',
            [id, user.id]
        ) as any[];

        if (instituicoes.length === 0) {
            return sendJSON(res, 404, {
                success: false,
                message: 'Instituição não encontrada ou você não tem permissão para editá-la'
            });
        }

        // Atualiza a instituição
        await query(
            'UPDATE INSTITUICAO SET NOME_INSTITUICAO = ?, CIDADE = ?, UF = ? WHERE ID_INSTITUICAO = ? AND ID_DOCENTE = ?',
            [nome, cidade || null, uf || null, id, user.id]
        );

        sendJSON(res, 200, {
            success: true,
            message: 'Instituição atualizada com sucesso',
            data: {
                id,
                nome,
                cidade: cidade || null,
                uf: uf || null
            }
        });

    } catch (error: any) {
        sendJSON(res, 500, {
            success: false,
            message: 'Erro interno do servidor'
        });
    }
}

/**
 * DELETE /instituicoes/:id - Exclui uma instituição
 */
export async function handleDeleteInstituicao(req: IncomingMessage, res: ServerResponse, id: number): Promise<void> {
    try {
        // Verifica autenticação
        const user = await authenticateToken(req);
        if (!user) {
            return sendJSON(res, 401, {
                success: false,
                message: 'Token de autenticação inválido ou ausente'
            });
        }

        // Verifica se a instituição pertence ao docente
        const instituicoes = await query(
            'SELECT ID_INSTITUICAO FROM INSTITUICAO WHERE ID_INSTITUICAO = ? AND ID_DOCENTE = ?',
            [id, user.id]
        ) as any[];

        if (instituicoes.length === 0) {
            return sendJSON(res, 404, {
                success: false,
                message: 'Instituição não encontrada ou você não tem permissão para excluí-la'
            });
        }

        // Exclui a instituição (o ON DELETE CASCADE vai cuidar dos relacionamentos)
        await query(
            'DELETE FROM INSTITUICAO WHERE ID_INSTITUICAO = ? AND ID_DOCENTE = ?',
            [id, user.id]
        );

        sendJSON(res, 200, {
            success: true,
            message: 'Instituição excluída com sucesso'
        });

    } catch (error: any) {
        sendJSON(res, 500, {
            success: false,
            message: 'Erro interno do servidor'
        });
    }
}

/**
 * GET /cursos?instituicaoId=X - Lista cursos de uma instituição
 */
export async function handleGetCursos(req: IncomingMessage, res: ServerResponse): Promise<void> {
    try {
        // Verifica autenticação
        const user = await authenticateToken(req);
        if (!user) {
            return sendJSON(res, 401, {
                success: false,
                message: 'Token de autenticação inválido ou ausente'
            });
        }

        // Obtém o ID da instituição da query string
        const url = req.url || '';
        const urlParts = url.split('?');
        const queryString = urlParts.length > 1 ? urlParts[1] : '';
        const params = new URLSearchParams(queryString);
        const instituicaoId = params.get('instituicaoId');

        if (!instituicaoId) {
            return sendJSON(res, 400, {
                success: false,
                message: 'ID da instituição é obrigatório'
            });
        }

        // Verifica se a instituição pertence ao docente
        const instituicoes = await query(
            'SELECT ID_INSTITUICAO FROM INSTITUICAO WHERE ID_INSTITUICAO = ? AND ID_DOCENTE = ?',
            [parseInt(instituicaoId), user.id]
        ) as any[];

        if (instituicoes.length === 0) {
            return sendJSON(res, 404, {
                success: false,
                message: 'Instituição não encontrada ou você não tem permissão para acessá-la'
            });
        }

        // Busca cursos da instituição
        const cursos = await query(
            `SELECT C.ID_CURSO, C.NOME_CURSO, C.MODALIDADE, C.AREA, C.PERIODO_TOTAL, I.NOME_INSTITUICAO
             FROM CURSO C
             INNER JOIN INSTITUICAO I ON C.ID_INSTITUICAO = I.ID_INSTITUICAO
             WHERE C.ID_INSTITUICAO = ?
             ORDER BY C.NOME_CURSO`,
            [parseInt(instituicaoId)]
        ) as any[];

        sendJSON(res, 200, {
            success: true,
            data: cursos.map(curso => ({
                id: curso.ID_CURSO,
                nome: curso.NOME_CURSO,
                modalidade: curso.MODALIDADE,
                area: curso.AREA,
                periodoTotal: curso.PERIODO_TOTAL,
                duracao: curso.PERIODO_TOTAL ? `${curso.PERIODO_TOTAL} períodos` : null,
                instituicaoNome: curso.NOME_INSTITUICAO
            }))
        });

    } catch (error: any) {
        sendJSON(res, 500, {
            success: false,
            message: 'Erro interno do servidor'
        });
    }
}

/**
 * POST /cursos - Cria um novo curso
 */
export async function handleCreateCurso(req: IncomingMessage, res: ServerResponse): Promise<void> {
    try {
        // Verifica autenticação
        const user = await authenticateToken(req);
        if (!user) {
            return sendJSON(res, 401, {
                success: false,
                message: 'Token de autenticação inválido ou ausente'
            });
        }

        const body = await readBody(req);
        const { nome, area, modalidade, periodoTotal, instituicaoId } = body;

        // Validação de campos obrigatórios
        if (!nome || !instituicaoId) {
            return sendJSON(res, 400, {
                success: false,
                message: 'Nome do curso e ID da instituição são obrigatórios'
            });
        }

        // Verifica se a instituição pertence ao docente
        const instituicoes = await query(
            'SELECT ID_INSTITUICAO, NOME_INSTITUICAO FROM INSTITUICAO WHERE ID_INSTITUICAO = ? AND ID_DOCENTE = ?',
            [parseInt(instituicaoId), user.id]
        ) as any[];

        if (instituicoes.length === 0) {
            return sendJSON(res, 404, {
                success: false,
                message: 'Instituição não encontrada ou você não tem permissão para criar cursos nela'
            });
        }

        // Insere o curso no banco
        const result = await query(
            'INSERT INTO CURSO (NOME_CURSO, MODALIDADE, AREA, PERIODO_TOTAL, ID_INSTITUICAO) VALUES (?, ?, ?, ?, ?)',
            [nome, modalidade || null, area || null, periodoTotal ? parseInt(periodoTotal) : null, parseInt(instituicaoId)]
        ) as any;

        sendJSON(res, 201, {
            success: true,
            message: 'Curso cadastrado com sucesso',
            data: {
                id: result.insertId,
                nome,
                area: area || null,
                modalidade: modalidade || null,
                periodoTotal: periodoTotal ? parseInt(periodoTotal) : null,
                instituicaoId: parseInt(instituicaoId),
                instituicaoNome: instituicoes[0].NOME_INSTITUICAO
            }
        });

    } catch (error: any) {
        sendJSON(res, 500, {
            success: false,
            message: 'Erro interno do servidor'
        });
    }
}

/**
 * PUT /cursos/:id - Atualiza um curso
 */
export async function handleUpdateCurso(req: IncomingMessage, res: ServerResponse, id: number): Promise<void> {
    try {
        // Verifica autenticação
        const user = await authenticateToken(req);
        if (!user) {
            return sendJSON(res, 401, {
                success: false,
                message: 'Token de autenticação inválido ou ausente'
            });
        }

        const body = await readBody(req);
        const { nome, area, modalidade, periodoTotal } = body;

        // Validação de campos obrigatórios
        if (!nome) {
            return sendJSON(res, 400, {
                success: false,
                message: 'Nome do curso é obrigatório'
            });
        }

        // Verifica se o curso existe e pertence a uma instituição do docente
        const cursos = await query(
            `SELECT C.ID_CURSO, C.ID_INSTITUICAO 
             FROM CURSO C
             INNER JOIN INSTITUICAO I ON C.ID_INSTITUICAO = I.ID_INSTITUICAO
             WHERE C.ID_CURSO = ? AND I.ID_DOCENTE = ?`,
            [id, user.id]
        ) as any[];

        if (cursos.length === 0) {
            return sendJSON(res, 404, {
                success: false,
                message: 'Curso não encontrado ou você não tem permissão para editá-lo'
            });
        }

        // Atualiza o curso
        await query(
            'UPDATE CURSO SET NOME_CURSO = ?, MODALIDADE = ?, AREA = ?, PERIODO_TOTAL = ? WHERE ID_CURSO = ?',
            [nome, modalidade || null, area || null, periodoTotal ? parseInt(periodoTotal) : null, id]
        );

        sendJSON(res, 200, {
            success: true,
            message: 'Curso atualizado com sucesso',
            data: {
                id,
                nome,
                area: area || null,
                modalidade: modalidade || null,
                periodoTotal: periodoTotal ? parseInt(periodoTotal) : null
            }
        });

    } catch (error: any) {
        sendJSON(res, 500, {
            success: false,
            message: 'Erro interno do servidor'
        });
    }
}

/**
 * DELETE /cursos/:id - Exclui um curso
 */
export async function handleDeleteCurso(req: IncomingMessage, res: ServerResponse, id: number): Promise<void> {
    try {
        // Verifica autenticação
        const user = await authenticateToken(req);
        if (!user) {
            return sendJSON(res, 401, {
                success: false,
                message: 'Token de autenticação inválido ou ausente'
            });
        }

        // Verifica se o curso existe e pertence a uma instituição do docente
        const cursos = await query(
            `SELECT C.ID_CURSO 
             FROM CURSO C
             INNER JOIN INSTITUICAO I ON C.ID_INSTITUICAO = I.ID_INSTITUICAO
             WHERE C.ID_CURSO = ? AND I.ID_DOCENTE = ?`,
            [id, user.id]
        ) as any[];

        if (cursos.length === 0) {
            return sendJSON(res, 404, {
                success: false,
                message: 'Curso não encontrado ou você não tem permissão para excluí-lo'
            });
        }

        // Exclui o curso (o ON DELETE CASCADE vai cuidar dos relacionamentos)
        await query(
            'DELETE FROM CURSO WHERE ID_CURSO = ?',
            [id]
        );

        sendJSON(res, 200, {
            success: true,
            message: 'Curso excluído com sucesso'
        });

    } catch (error: any) {
        sendJSON(res, 500, {
            success: false,
            message: 'Erro interno do servidor'
        });
    }
}

/**
 * GET /disciplinas?cursoId=X - Lista disciplinas de um curso
 */
export async function handleGetDisciplinas(req: IncomingMessage, res: ServerResponse): Promise<void> {
    try {
        // Verifica autenticação
        const user = await authenticateToken(req);
        if (!user) {
            return sendJSON(res, 401, {
                success: false,
                message: 'Token de autenticação inválido ou ausente'
            });
        }

        // Obtém o ID do curso da query string
        const url = req.url || '';
        const urlParts = url.split('?');
        const queryString = urlParts.length > 1 ? urlParts[1] : '';
        const params = new URLSearchParams(queryString);
        const cursoId = params.get('cursoId');

        if (!cursoId) {
            return sendJSON(res, 400, {
                success: false,
                message: 'ID do curso é obrigatório'
            });
        }

        // Verifica se o curso pertence a uma instituição do docente
        const cursos = await query(
            `SELECT C.ID_CURSO, C.NOME_CURSO
             FROM CURSO C
             INNER JOIN INSTITUICAO I ON C.ID_INSTITUICAO = I.ID_INSTITUICAO
             WHERE C.ID_CURSO = ? AND I.ID_DOCENTE = ?`,
            [parseInt(cursoId), user.id]
        ) as any[];

        if (cursos.length === 0) {
            return sendJSON(res, 404, {
                success: false,
                message: 'Curso não encontrado ou você não tem permissão para acessá-lo'
            });
        }

        // Busca disciplinas do curso
        const disciplinas = await query(
            `SELECT D.ID_DISCIPLINA, D.NOME_DISCIPLINA, D.SIGLA, D.CODIGO, D.PERIODO, C.NOME_CURSO
             FROM DISCIPLINA D
             INNER JOIN CURSO C ON D.ID_CURSO = C.ID_CURSO
             WHERE D.ID_CURSO = ?
             ORDER BY D.PERIODO, D.NOME_DISCIPLINA`,
            [parseInt(cursoId)]
        ) as any[];

        sendJSON(res, 200, {
            success: true,
            data: disciplinas.map(disciplina => ({
                id: disciplina.ID_DISCIPLINA,
                nome: disciplina.NOME_DISCIPLINA,
                sigla: disciplina.SIGLA,
                codigo: disciplina.CODIGO,
                periodo: disciplina.PERIODO,
                cursoNome: disciplina.NOME_CURSO
            }))
        });

    } catch (error: any) {
        sendJSON(res, 500, {
            success: false,
            message: 'Erro interno do servidor'
        });
    }
}

/**
 * POST /disciplinas - Cria uma nova disciplina
 */
export async function handleCreateDisciplina(req: IncomingMessage, res: ServerResponse): Promise<void> {
    try {
        // Verifica autenticação
        const user = await authenticateToken(req);
        if (!user) {
            return sendJSON(res, 401, {
                success: false,
                message: 'Token de autenticação inválido ou ausente'
            });
        }

        const body = await readBody(req);
        const { nome, sigla, codigo, periodo, cursoId } = body;

        // Validação de campos obrigatórios
        if (!nome || !sigla || !cursoId) {
            return sendJSON(res, 400, {
                success: false,
                message: 'Nome da disciplina, sigla e ID do curso são obrigatórios'
            });
        }

        // Verifica se o curso pertence a uma instituição do docente
        const cursos = await query(
            `SELECT C.ID_CURSO, C.NOME_CURSO
             FROM CURSO C
             INNER JOIN INSTITUICAO I ON C.ID_INSTITUICAO = I.ID_INSTITUICAO
             WHERE C.ID_CURSO = ? AND I.ID_DOCENTE = ?`,
            [parseInt(cursoId), user.id]
        ) as any[];

        if (cursos.length === 0) {
            return sendJSON(res, 404, {
                success: false,
                message: 'Curso não encontrado ou você não tem permissão para criar disciplinas nele'
            });
        }

        // Insere a disciplina no banco
        const result = await query(
            'INSERT INTO DISCIPLINA (NOME_DISCIPLINA, SIGLA, CODIGO, PERIODO, ID_CURSO) VALUES (?, ?, ?, ?, ?)',
            [nome, sigla, codigo || null, periodo || null, parseInt(cursoId)]
        ) as any;

        sendJSON(res, 201, {
            success: true,
            message: 'Disciplina cadastrada com sucesso',
            data: {
                id: result.insertId,
                nome,
                sigla,
                codigo: codigo || null,
                periodo: periodo || null,
                cursoId: parseInt(cursoId),
                cursoNome: cursos[0].NOME_CURSO
            }
        });

    } catch (error: any) {
        sendJSON(res, 500, {
            success: false,
            message: 'Erro interno do servidor'
        });
    }
}

/**
 * PUT /disciplinas/:id - Atualiza uma disciplina
 */
export async function handleUpdateDisciplina(req: IncomingMessage, res: ServerResponse, id: number): Promise<void> {
    try {
        // Verifica autenticação
        const user = await authenticateToken(req);
        if (!user) {
            return sendJSON(res, 401, {
                success: false,
                message: 'Token de autenticação inválido ou ausente'
            });
        }

        const body = await readBody(req);
        const { nome, sigla, codigo, periodo } = body;

        // Validação de campos obrigatórios
        if (!nome || !sigla) {
            return sendJSON(res, 400, {
                success: false,
                message: 'Nome da disciplina e sigla são obrigatórios'
            });
        }

        // Verifica se a disciplina existe e pertence a um curso do docente
        const disciplinas = await query(
            `SELECT D.ID_DISCIPLINA, D.ID_CURSO
             FROM DISCIPLINA D
             INNER JOIN CURSO C ON D.ID_CURSO = C.ID_CURSO
             INNER JOIN INSTITUICAO I ON C.ID_INSTITUICAO = I.ID_INSTITUICAO
             WHERE D.ID_DISCIPLINA = ? AND I.ID_DOCENTE = ?`,
            [id, user.id]
        ) as any[];

        if (disciplinas.length === 0) {
            return sendJSON(res, 404, {
                success: false,
                message: 'Disciplina não encontrada ou você não tem permissão para editá-la'
            });
        }

        // Atualiza a disciplina
        await query(
            'UPDATE DISCIPLINA SET NOME_DISCIPLINA = ?, SIGLA = ?, CODIGO = ?, PERIODO = ? WHERE ID_DISCIPLINA = ?',
            [nome, sigla, codigo || null, periodo || null, id]
        );

        sendJSON(res, 200, {
            success: true,
            message: 'Disciplina atualizada com sucesso',
            data: {
                id,
                nome,
                sigla,
                codigo: codigo || null,
                periodo: periodo || null
            }
        });

    } catch (error: any) {
        sendJSON(res, 500, {
            success: false,
            message: 'Erro interno do servidor'
        });
    }
}

/**
 * DELETE /disciplinas/:id - Exclui uma disciplina
 */
export async function handleDeleteDisciplina(req: IncomingMessage, res: ServerResponse, id: number): Promise<void> {
    try {
        // Verifica autenticação
        const user = await authenticateToken(req);
        if (!user) {
            return sendJSON(res, 401, {
                success: false,
                message: 'Token de autenticação inválido ou ausente'
            });
        }

        // Verifica se a disciplina existe e pertence a um curso do docente
        const disciplinas = await query(
            `SELECT D.ID_DISCIPLINA
             FROM DISCIPLINA D
             INNER JOIN CURSO C ON D.ID_CURSO = C.ID_CURSO
             INNER JOIN INSTITUICAO I ON C.ID_INSTITUICAO = I.ID_INSTITUICAO
             WHERE D.ID_DISCIPLINA = ? AND I.ID_DOCENTE = ?`,
            [id, user.id]
        ) as any[];

        if (disciplinas.length === 0) {
            return sendJSON(res, 404, {
                success: false,
                message: 'Disciplina não encontrada ou você não tem permissão para excluí-la'
            });
        }

        // Exclui a disciplina (o ON DELETE CASCADE vai cuidar dos relacionamentos)
        await query(
            'DELETE FROM DISCIPLINA WHERE ID_DISCIPLINA = ?',
            [id]
        );

        sendJSON(res, 200, {
            success: true,
            message: 'Disciplina excluída com sucesso'
        });

    } catch (error: any) {
        sendJSON(res, 500, {
            success: false,
            message: 'Erro interno do servidor'
        });
    }
}

