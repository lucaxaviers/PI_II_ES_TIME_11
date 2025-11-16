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
 * Trata erros de Foreign Key e retorna mensagens claras
 */
function handleForeignKeyError(error: any, entityType: string): { erro: boolean; mensagem: string } | null {
    // Detecta erros de Foreign Key
    const isForeignKeyError = 
        error.code === 'ER_ROW_IS_REFERENCED_2' || 
        error.message?.includes('foreign key constraint fails') ||
        error.message?.includes('Cannot delete or update a parent row');

    if (!isForeignKeyError) {
        return null; // Não é erro de Foreign Key
    }

    const errorMsg = error.message?.toLowerCase() || '';
    
    // Identifica qual tabela está impedindo a exclusão
    const blockingTable = 
        errorMsg.includes('curso') ? 'curso' :
        errorMsg.includes('disciplina') ? 'disciplina' :
        errorMsg.includes('turma') ? 'turma' :
        errorMsg.includes('aluno') ? 'aluno' :
        errorMsg.includes('componente') || errorMsg.includes('componente_nota') ? 'componente' :
        errorMsg.includes('nota') || errorMsg.includes('auditoria') ? 'nota' :
        errorMsg.includes('instituicao') ? 'instituicao' :
        null;

    // Retorna mensagens específicas baseadas na entidade que está sendo excluída
    switch (entityType.toLowerCase()) {
        case 'instituicao':
            return {
                erro: true,
                mensagem: 'Não é possível excluir a instituição porque existem cursos, disciplinas, turmas, alunos ou notas vinculadas.'
            };
        
        case 'curso':
            return {
                erro: true,
                mensagem: 'Não é possível excluir o curso porque existem disciplinas vinculadas.'
            };
        
        case 'disciplina':
            if (blockingTable === 'turma') {
                return {
                    erro: true,
                    mensagem: 'Não é possível excluir a disciplina porque existem turmas vinculadas.'
                };
            } else if (blockingTable === 'componente') {
                return {
                    erro: true,
                    mensagem: 'Não é possível excluir a disciplina porque existem componentes de nota vinculados.'
                };
            }
            return {
                erro: true,
                mensagem: 'Não é possível excluir a disciplina porque existem turmas ou componentes vinculados.'
            };
        
        case 'turma':
            if (blockingTable === 'aluno') {
                return {
                    erro: true,
                    mensagem: 'Não é possível excluir a turma porque existem alunos vinculados.'
                };
            } else if (blockingTable === 'nota') {
                return {
                    erro: true,
                    mensagem: 'Não é possível excluir a turma porque existem notas vinculadas.'
                };
            }
            return {
                erro: true,
                mensagem: 'Não é possível excluir a turma porque existem alunos ou notas vinculadas.'
            };
        
        case 'aluno':
            return {
                erro: true,
                mensagem: 'Não é possível excluir o aluno porque há notas registradas para ele.'
            };
        
        case 'componente':
            return {
                erro: true,
                mensagem: 'Não é possível excluir o componente porque existem notas vinculadas a ele.'
            };
        
        default:
            return {
                erro: true,
                mensagem: 'Não é possível excluir este item porque existem registros vinculados.'
            };
    }
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
        // Trata erros de Foreign Key
        const fkError = handleForeignKeyError(error, 'instituicao');
        if (fkError) {
            return sendJSON(res, 400, fkError);
        }
        
        console.error('Erro ao excluir instituição:', error);
        sendJSON(res, 500, {
            erro: true,
            mensagem: 'Erro interno do servidor'
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
        // Trata erros de Foreign Key
        const fkError = handleForeignKeyError(error, 'curso');
        if (fkError) {
            return sendJSON(res, 400, fkError);
        }
        
        console.error('Erro ao excluir curso:', error);
        sendJSON(res, 500, {
            erro: true,
            mensagem: 'Erro interno do servidor'
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
        // Trata erros de Foreign Key
        const fkError = handleForeignKeyError(error, 'disciplina');
        if (fkError) {
            return sendJSON(res, 400, fkError);
        }
        
        console.error('Erro ao excluir disciplina:', error);
        sendJSON(res, 500, {
            erro: true,
            mensagem: 'Erro interno do servidor'
        });
    }
}

/**
 * GET /turmas?disciplinaId=X - Lista turmas de uma disciplina
 */
export async function handleGetTurmas(req: IncomingMessage, res: ServerResponse): Promise<void> {
    try {
        // Verifica autenticação
        const user = await authenticateToken(req);
        if (!user) {
            return sendJSON(res, 401, {
                success: false,
                message: 'Token de autenticação inválido ou ausente'
            });
        }

        // Obtém o ID da disciplina da query string
        const url = req.url || '';
        const urlParts = url.split('?');
        const queryString = urlParts.length > 1 ? urlParts[1] : '';
        const params = new URLSearchParams(queryString);
        const disciplinaId = params.get('disciplinaId');

        if (!disciplinaId) {
            return sendJSON(res, 400, {
                success: false,
                message: 'ID da disciplina é obrigatório'
            });
        }

        // Verifica se a disciplina pertence a um curso do docente
        const disciplinas = await query(
            `SELECT D.ID_DISCIPLINA, D.NOME_DISCIPLINA
             FROM DISCIPLINA D
             INNER JOIN CURSO C ON D.ID_CURSO = C.ID_CURSO
             INNER JOIN INSTITUICAO I ON C.ID_INSTITUICAO = I.ID_INSTITUICAO
             WHERE D.ID_DISCIPLINA = ? AND I.ID_DOCENTE = ?`,
            [parseInt(disciplinaId), user.id]
        ) as any[];

        if (disciplinas.length === 0) {
            return sendJSON(res, 404, {
                success: false,
                message: 'Disciplina não encontrada ou você não tem permissão para acessá-la'
            });
        }

        // Busca turmas da disciplina com contagem real de alunos
        const turmas = await query(
            `SELECT 
                T.ID_TURMA, 
                T.NOME_TURMA, 
                D.NOME_DISCIPLINA,
                COUNT(A.ID_ALUNO) as QTD_ALUNOS
             FROM TURMA T
             INNER JOIN DISCIPLINA D ON T.ID_DISCIPLINA = D.ID_DISCIPLINA
             LEFT JOIN ALUNO A ON T.ID_TURMA = A.ID_TURMA
             WHERE T.ID_DISCIPLINA = ?
             GROUP BY T.ID_TURMA, T.NOME_TURMA, D.NOME_DISCIPLINA
             ORDER BY T.NOME_TURMA`,
            [parseInt(disciplinaId)]
        ) as any[];

        sendJSON(res, 200, {
            success: true,
            data: turmas.map(turma => ({
                id: turma.ID_TURMA,
                nome: turma.NOME_TURMA,
                qtdAlunos: Number(turma.QTD_ALUNOS) || 0,
                disciplinaNome: turma.NOME_DISCIPLINA
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
 * POST /turmas - Cria uma nova turma
 */
export async function handleCreateTurma(req: IncomingMessage, res: ServerResponse): Promise<void> {
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
        const { nome, sigla, codigo, disciplinaId } = body;

        // Validação de campos obrigatórios
        if (!nome || !disciplinaId) {
            return sendJSON(res, 400, {
                success: false,
                message: 'Nome da turma e ID da disciplina são obrigatórios'
            });
        }

        // Verifica se a disciplina pertence a um curso do docente
        const disciplinas = await query(
            `SELECT D.ID_DISCIPLINA, D.NOME_DISCIPLINA
             FROM DISCIPLINA D
             INNER JOIN CURSO C ON D.ID_CURSO = C.ID_CURSO
             INNER JOIN INSTITUICAO I ON C.ID_INSTITUICAO = I.ID_INSTITUICAO
             WHERE D.ID_DISCIPLINA = ? AND I.ID_DOCENTE = ?`,
            [parseInt(disciplinaId), user.id]
        ) as any[];

        if (disciplinas.length === 0) {
            return sendJSON(res, 404, {
                success: false,
                message: 'Disciplina não encontrada ou você não tem permissão para criar turmas nela'
            });
        }

        // Monta o nome completo da turma (incluindo sigla e código se fornecidos)
        let nomeCompleto = nome;
        if (sigla) {
            nomeCompleto = `${nome} (${sigla})`;
        }
        if (codigo) {
            nomeCompleto = `${nome} [${codigo}]`;
        }
        if (sigla && codigo) {
            nomeCompleto = `${nome} (${sigla}) [${codigo}]`;
        }

        // Insere a turma no banco
        const result = await query(
            'INSERT INTO TURMA (NOME_TURMA, QTD_ALUNOS, ID_DISCIPLINA) VALUES (?, ?, ?)',
            [nomeCompleto, 0, parseInt(disciplinaId)]
        ) as any;

        sendJSON(res, 201, {
            success: true,
            message: 'Turma cadastrada com sucesso',
            data: {
                id: result.insertId,
                nome: nomeCompleto,
                sigla: sigla || null,
                codigo: codigo || null,
                qtdAlunos: 0,
                disciplinaId: parseInt(disciplinaId),
                disciplinaNome: disciplinas[0].NOME_DISCIPLINA
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
 * PUT /turmas/:id - Atualiza uma turma
 */
export async function handleUpdateTurma(req: IncomingMessage, res: ServerResponse, id: number): Promise<void> {
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
        const { nome, sigla, codigo } = body;

        // Validação de campos obrigatórios
        if (!nome) {
            return sendJSON(res, 400, {
                success: false,
                message: 'Nome da turma é obrigatório'
            });
        }

        // Verifica se a turma existe e pertence a uma disciplina do docente
        const turmas = await query(
            `SELECT T.ID_TURMA, T.ID_DISCIPLINA
             FROM TURMA T
             INNER JOIN DISCIPLINA D ON T.ID_DISCIPLINA = D.ID_DISCIPLINA
             INNER JOIN CURSO C ON D.ID_CURSO = C.ID_CURSO
             INNER JOIN INSTITUICAO I ON C.ID_INSTITUICAO = I.ID_INSTITUICAO
             WHERE T.ID_TURMA = ? AND I.ID_DOCENTE = ?`,
            [id, user.id]
        ) as any[];

        if (turmas.length === 0) {
            return sendJSON(res, 404, {
                success: false,
                message: 'Turma não encontrada ou você não tem permissão para editá-la'
            });
        }

        // Monta o nome completo da turma (incluindo sigla e código se fornecidos)
        let nomeCompleto = nome;
        if (sigla) {
            nomeCompleto = `${nome} (${sigla})`;
        }
        if (codigo) {
            nomeCompleto = `${nome} [${codigo}]`;
        }
        if (sigla && codigo) {
            nomeCompleto = `${nome} (${sigla}) [${codigo}]`;
        }

        // Atualiza a turma
        await query(
            'UPDATE TURMA SET NOME_TURMA = ? WHERE ID_TURMA = ?',
            [nomeCompleto, id]
        );

        sendJSON(res, 200, {
            success: true,
            message: 'Turma atualizada com sucesso',
            data: {
                id,
                nome: nomeCompleto,
                sigla: sigla || null,
                codigo: codigo || null
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
 * DELETE /turmas/:id - Exclui uma turma
 */
export async function handleDeleteTurma(req: IncomingMessage, res: ServerResponse, id: number): Promise<void> {
    try {
        // Verifica autenticação
        const user = await authenticateToken(req);
        if (!user) {
            return sendJSON(res, 401, {
                success: false,
                message: 'Token de autenticação inválido ou ausente'
            });
        }

        // Verifica se a turma existe e pertence a uma disciplina do docente
        const turmas = await query(
            `SELECT T.ID_TURMA
             FROM TURMA T
             INNER JOIN DISCIPLINA D ON T.ID_DISCIPLINA = D.ID_DISCIPLINA
             INNER JOIN CURSO C ON D.ID_CURSO = C.ID_CURSO
             INNER JOIN INSTITUICAO I ON C.ID_INSTITUICAO = I.ID_INSTITUICAO
             WHERE T.ID_TURMA = ? AND I.ID_DOCENTE = ?`,
            [id, user.id]
        ) as any[];

        if (turmas.length === 0) {
            return sendJSON(res, 404, {
                success: false,
                message: 'Turma não encontrada ou você não tem permissão para excluí-la'
            });
        }

        // Exclui a turma (o ON DELETE CASCADE vai cuidar dos relacionamentos)
        await query(
            'DELETE FROM TURMA WHERE ID_TURMA = ?',
            [id]
        );

        sendJSON(res, 200, {
            success: true,
            message: 'Turma excluída com sucesso'
        });

    } catch (error: any) {
        // Trata erros de Foreign Key
        const fkError = handleForeignKeyError(error, 'turma');
        if (fkError) {
            return sendJSON(res, 400, fkError);
        }
        
        console.error('Erro ao excluir turma:', error);
        sendJSON(res, 500, {
            erro: true,
            mensagem: 'Erro interno do servidor'
        });
    }
}

/**
 * GET /alunos - Lista alunos de uma turma
 */
export async function handleGetAlunos(req: IncomingMessage, res: ServerResponse): Promise<void> {
    try {
        // Verifica autenticação
        const user = await authenticateToken(req);
        if (!user) {
            return sendJSON(res, 401, {
                success: false,
                message: 'Token de autenticação inválido ou ausente'
            });
        }

        // Obtém o ID da turma da query string
        const url = req.url || '';
        const urlParts = url.split('?');
        const queryString = urlParts.length > 1 ? urlParts[1] : '';
        const params = new URLSearchParams(queryString);
        const turmaId = params.get('turmaId');

        if (!turmaId) {
            return sendJSON(res, 400, {
                success: false,
                message: 'ID da turma é obrigatório'
            });
        }

        // Verifica se a turma pertence a uma disciplina do docente
        const turmas = await query(
            `SELECT T.ID_TURMA, T.NOME_TURMA
             FROM TURMA T
             INNER JOIN DISCIPLINA D ON T.ID_DISCIPLINA = D.ID_DISCIPLINA
             INNER JOIN CURSO C ON D.ID_CURSO = C.ID_CURSO
             INNER JOIN INSTITUICAO I ON C.ID_INSTITUICAO = I.ID_INSTITUICAO
             WHERE T.ID_TURMA = ? AND I.ID_DOCENTE = ?`,
            [parseInt(turmaId), user.id]
        ) as any[];

        if (turmas.length === 0) {
            return sendJSON(res, 404, {
                success: false,
                message: 'Turma não encontrada ou você não tem permissão para acessá-la'
            });
        }

        // Busca alunos da turma
        const alunos = await query(
            `SELECT A.ID_ALUNO, A.RA, A.NOME
             FROM ALUNO A
             WHERE A.ID_TURMA = ?
             ORDER BY A.NOME`,
            [parseInt(turmaId)]
        ) as any[];

        sendJSON(res, 200, {
            success: true,
            data: alunos.map(aluno => ({
                id: aluno.ID_ALUNO,
                matricula: aluno.RA,
                ra: aluno.RA,
                nome: aluno.NOME
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
 * POST /alunos - Cria um novo aluno
 */
export async function handleCreateAluno(req: IncomingMessage, res: ServerResponse): Promise<void> {
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
        const { matricula, ra, nome, turmaId } = body;

        // Validação de campos obrigatórios
        const raValue = ra || matricula;
        if (!raValue || !raValue.trim()) {
            return sendJSON(res, 400, {
                success: false,
                message: 'RA é obrigatório'
            });
        }

        if (!nome || !nome.trim()) {
            return sendJSON(res, 400, {
                success: false,
                message: 'Nome é obrigatório'
            });
        }

        if (!turmaId) {
            return sendJSON(res, 400, {
                success: false,
                message: 'ID da turma é obrigatório'
            });
        }

        // Verifica se a turma pertence a uma disciplina do docente
        const turmas = await query(
            `SELECT T.ID_TURMA
             FROM TURMA T
             INNER JOIN DISCIPLINA D ON T.ID_DISCIPLINA = D.ID_DISCIPLINA
             INNER JOIN CURSO C ON D.ID_CURSO = C.ID_CURSO
             INNER JOIN INSTITUICAO I ON C.ID_INSTITUICAO = I.ID_INSTITUICAO
             WHERE T.ID_TURMA = ? AND I.ID_DOCENTE = ?`,
            [parseInt(turmaId), user.id]
        ) as any[];

        if (turmas.length === 0) {
            return sendJSON(res, 404, {
                success: false,
                message: 'Turma não encontrada ou você não tem permissão para adicionar alunos'
            });
        }

        // Verifica se já existe aluno com o mesmo RA na turma
        const alunosExistentes = await query(
            'SELECT ID_ALUNO FROM ALUNO WHERE RA = ? AND ID_TURMA = ?',
            [raValue.trim(), parseInt(turmaId)]
        ) as any[];

        if (alunosExistentes.length > 0) {
            return sendJSON(res, 409, {
                success: false,
                message: 'Já existe um aluno com este RA nesta turma'
            });
        }

        // Insere o aluno
        const result = await query(
            'INSERT INTO ALUNO (RA, NOME, ID_TURMA) VALUES (?, ?, ?)',
            [raValue.trim(), nome.trim(), parseInt(turmaId)]
        ) as any;

        sendJSON(res, 201, {
            success: true,
            message: 'Aluno cadastrado com sucesso',
            data: {
                id: result.insertId,
                ra: raValue.trim(),
                nome: nome.trim(),
                turmaId: parseInt(turmaId)
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
 * PUT /alunos/:id - Atualiza um aluno
 */
export async function handleUpdateAluno(req: IncomingMessage, res: ServerResponse, id: number): Promise<void> {
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
        const { nome } = body;

        // Validação de campos obrigatórios
        if (!nome || !nome.trim()) {
            return sendJSON(res, 400, {
                success: false,
                message: 'Nome é obrigatório'
            });
        }

        // Verifica se o aluno existe e pertence a uma turma do docente
        const alunos = await query(
            `SELECT A.ID_ALUNO, A.RA, A.NOME, A.ID_TURMA
             FROM ALUNO A
             INNER JOIN TURMA T ON A.ID_TURMA = T.ID_TURMA
             INNER JOIN DISCIPLINA D ON T.ID_DISCIPLINA = D.ID_DISCIPLINA
             INNER JOIN CURSO C ON D.ID_CURSO = C.ID_CURSO
             INNER JOIN INSTITUICAO I ON C.ID_INSTITUICAO = I.ID_INSTITUICAO
             WHERE A.ID_ALUNO = ? AND I.ID_DOCENTE = ?`,
            [id, user.id]
        ) as any[];

        if (alunos.length === 0) {
            return sendJSON(res, 404, {
                success: false,
                message: 'Aluno não encontrado ou você não tem permissão para editá-lo'
            });
        }

        // Atualiza o aluno (apenas o nome, RA não pode ser alterado)
        await query(
            'UPDATE ALUNO SET NOME = ? WHERE ID_ALUNO = ?',
            [nome.trim(), id]
        );

        sendJSON(res, 200, {
            success: true,
            message: 'Aluno atualizado com sucesso',
            data: {
                id: id,
                ra: alunos[0].RA,
                nome: nome.trim()
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
 * DELETE /alunos/:id - Exclui um aluno
 */
export async function handleDeleteAluno(req: IncomingMessage, res: ServerResponse, id: number): Promise<void> {
    try {
        // Verifica autenticação
        const user = await authenticateToken(req);
        if (!user) {
            return sendJSON(res, 401, {
                success: false,
                message: 'Token de autenticação inválido ou ausente'
            });
        }

        // Verifica se o aluno existe e pertence a uma turma do docente
        const alunos = await query(
            `SELECT A.ID_ALUNO
             FROM ALUNO A
             INNER JOIN TURMA T ON A.ID_TURMA = T.ID_TURMA
             INNER JOIN DISCIPLINA D ON T.ID_DISCIPLINA = D.ID_DISCIPLINA
             INNER JOIN CURSO C ON D.ID_CURSO = C.ID_CURSO
             INNER JOIN INSTITUICAO I ON C.ID_INSTITUICAO = I.ID_INSTITUICAO
             WHERE A.ID_ALUNO = ? AND I.ID_DOCENTE = ?`,
            [id, user.id]
        ) as any[];

        if (alunos.length === 0) {
            return sendJSON(res, 404, {
                success: false,
                message: 'Aluno não encontrado ou você não tem permissão para excluí-lo'
            });
        }

        // Exclui o aluno
        await query(
            'DELETE FROM ALUNO WHERE ID_ALUNO = ?',
            [id]
        );

        sendJSON(res, 200, {
            success: true,
            message: 'Aluno excluído com sucesso'
        });

    } catch (error: any) {
        // Trata erros de Foreign Key
        const fkError = handleForeignKeyError(error, 'aluno');
        if (fkError) {
            return sendJSON(res, 400, fkError);
        }
        
        console.error('Erro ao excluir aluno:', error);
        sendJSON(res, 500, {
            erro: true,
            mensagem: 'Erro interno do servidor'
        });
    }
}

// ============================================================================
// ROTAS DE COMPONENTES DE NOTA
// ============================================================================

/**
 * GET /componentes?disciplinaId=X - Lista componentes de nota de uma disciplina
 */
export async function handleGetComponentes(req: IncomingMessage, res: ServerResponse): Promise<void> {
    try {
        // Verifica autenticação
        const user = await authenticateToken(req);
        if (!user) {
            return sendJSON(res, 401, {
                success: false,
                message: 'Token de autenticação inválido ou ausente'
            });
        }

        // Extrai disciplinaId da query string
        const url = new URL(req.url || '', `http://${req.headers.host}`);
        const disciplinaId = url.searchParams.get('disciplinaId');

        if (!disciplinaId) {
            return sendJSON(res, 400, {
                success: false,
                message: 'disciplinaId é obrigatório'
            });
        }

        // Verifica se a disciplina pertence ao docente
        const disciplinas = await query(
            `SELECT D.ID_DISCIPLINA
             FROM DISCIPLINA D
             INNER JOIN CURSO C ON D.ID_CURSO = C.ID_CURSO
             INNER JOIN INSTITUICAO I ON C.ID_INSTITUICAO = I.ID_INSTITUICAO
             WHERE D.ID_DISCIPLINA = ? AND I.ID_DOCENTE = ?`,
            [parseInt(disciplinaId), user.id]
        ) as any[];

        if (disciplinas.length === 0) {
            return sendJSON(res, 404, {
                success: false,
                message: 'Disciplina não encontrada ou você não tem permissão para acessá-la'
            });
        }

        // Busca componentes da disciplina
        const componentes = await query(
            `SELECT 
                ID_COMPONENTE as id,
                NOME_COMPONENTE as nome,
                SIGLA as sigla,
                DESCRICAO as descricao,
                PESO as peso
             FROM COMPONENTE_NOTA
             WHERE ID_DISCIPLINA = ?
             ORDER BY NOME_COMPONENTE`,
            [parseInt(disciplinaId)]
        ) as any[];

        sendJSON(res, 200, {
            success: true,
            data: componentes
        });

    } catch (error: any) {
        console.error('Erro ao buscar componentes:', error);
        sendJSON(res, 500, {
            success: false,
            message: 'Erro interno do servidor'
        });
    }
}

/**
 * POST /componentes - Cria um novo componente de nota
 */
export async function handleCreateComponente(req: IncomingMessage, res: ServerResponse): Promise<void> {
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
        const { nome, sigla, descricao, peso, disciplinaId } = body;

        // Validação de campos obrigatórios
        if (!nome || !nome.trim()) {
            return sendJSON(res, 400, {
                success: false,
                message: 'Nome é obrigatório'
            });
        }

        if (!sigla || !sigla.trim()) {
            return sendJSON(res, 400, {
                success: false,
                message: 'Sigla é obrigatória'
            });
        }

        if (!disciplinaId) {
            return sendJSON(res, 400, {
                success: false,
                message: 'disciplinaId é obrigatório'
            });
        }

        // Verifica se a disciplina pertence ao docente
        const disciplinas = await query(
            `SELECT D.ID_DISCIPLINA
             FROM DISCIPLINA D
             INNER JOIN CURSO C ON D.ID_CURSO = C.ID_CURSO
             INNER JOIN INSTITUICAO I ON C.ID_INSTITUICAO = I.ID_INSTITUICAO
             WHERE D.ID_DISCIPLINA = ? AND I.ID_DOCENTE = ?`,
            [parseInt(disciplinaId), user.id]
        ) as any[];

        if (disciplinas.length === 0) {
            return sendJSON(res, 404, {
                success: false,
                message: 'Disciplina não encontrada ou você não tem permissão para editá-la'
            });
        }

        // Insere o componente
        const result = await query(
            `INSERT INTO COMPONENTE_NOTA (NOME_COMPONENTE, SIGLA, DESCRICAO, PESO, ID_DISCIPLINA)
             VALUES (?, ?, ?, ?, ?)`,
            [
                nome.trim(),
                sigla.trim().toUpperCase(),
                descricao ? descricao.trim() : null,
                peso ? parseFloat(peso) : null,
                parseInt(disciplinaId)
            ]
        ) as any;

        sendJSON(res, 201, {
            success: true,
            message: 'Componente criado com sucesso',
            data: {
                id: result.insertId,
                nome: nome.trim(),
                sigla: sigla.trim().toUpperCase(),
                descricao: descricao ? descricao.trim() : null,
                peso: peso ? parseFloat(peso) : null
            }
        });

    } catch (error: any) {
        console.error('Erro ao criar componente:', error);
        
        // Verifica se é erro de duplicação
        if (error.code === 'ER_DUP_ENTRY') {
            return sendJSON(res, 409, {
                success: false,
                message: 'Já existe um componente com esta sigla nesta disciplina'
            });
        }

        sendJSON(res, 500, {
            success: false,
            message: 'Erro interno do servidor'
        });
    }
}

/**
 * PUT /componentes/:id - Atualiza um componente de nota
 */
export async function handleUpdateComponente(req: IncomingMessage, res: ServerResponse, id: number): Promise<void> {
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
        const { nome, sigla, descricao, peso } = body;

        // Validação de campos obrigatórios
        if (!nome || !nome.trim()) {
            return sendJSON(res, 400, {
                success: false,
                message: 'Nome é obrigatório'
            });
        }

        if (!sigla || !sigla.trim()) {
            return sendJSON(res, 400, {
                success: false,
                message: 'Sigla é obrigatória'
            });
        }

        // Verifica se o componente existe e pertence a uma disciplina do docente
        const componentes = await query(
            `SELECT CN.ID_COMPONENTE, CN.SIGLA
             FROM COMPONENTE_NOTA CN
             INNER JOIN DISCIPLINA D ON CN.ID_DISCIPLINA = D.ID_DISCIPLINA
             INNER JOIN CURSO C ON D.ID_CURSO = C.ID_CURSO
             INNER JOIN INSTITUICAO I ON C.ID_INSTITUICAO = I.ID_INSTITUICAO
             WHERE CN.ID_COMPONENTE = ? AND I.ID_DOCENTE = ?`,
            [id, user.id]
        ) as any[];

        if (componentes.length === 0) {
            return sendJSON(res, 404, {
                success: false,
                message: 'Componente não encontrado ou você não tem permissão para editá-lo'
            });
        }

        // Atualiza o componente
        await query(
            `UPDATE COMPONENTE_NOTA 
             SET NOME_COMPONENTE = ?, SIGLA = ?, DESCRICAO = ?, PESO = ?
             WHERE ID_COMPONENTE = ?`,
            [
                nome.trim(),
                sigla.trim().toUpperCase(),
                descricao ? descricao.trim() : null,
                peso ? parseFloat(peso) : null,
                id
            ]
        );

        sendJSON(res, 200, {
            success: true,
            message: 'Componente atualizado com sucesso',
            data: {
                id: id,
                nome: nome.trim(),
                sigla: sigla.trim().toUpperCase(),
                descricao: descricao ? descricao.trim() : null,
                peso: peso ? parseFloat(peso) : null
            }
        });

    } catch (error: any) {
        console.error('Erro ao atualizar componente:', error);
        
        // Verifica se é erro de duplicação
        if (error.code === 'ER_DUP_ENTRY') {
            return sendJSON(res, 409, {
                success: false,
                message: 'Já existe um componente com esta sigla nesta disciplina'
            });
        }

        sendJSON(res, 500, {
            success: false,
            message: 'Erro interno do servidor'
        });
    }
}

/**
 * DELETE /componentes/:id - Exclui um componente de nota
 */
export async function handleDeleteComponente(req: IncomingMessage, res: ServerResponse, id: number): Promise<void> {
    try {
        // Verifica autenticação
        const user = await authenticateToken(req);
        if (!user) {
            return sendJSON(res, 401, {
                success: false,
                message: 'Token de autenticação inválido ou ausente'
            });
        }

        // Verifica se o componente existe e pertence a uma disciplina do docente
        const componentes = await query(
            `SELECT CN.ID_COMPONENTE
             FROM COMPONENTE_NOTA CN
             INNER JOIN DISCIPLINA D ON CN.ID_DISCIPLINA = D.ID_DISCIPLINA
             INNER JOIN CURSO C ON D.ID_CURSO = C.ID_CURSO
             INNER JOIN INSTITUICAO I ON C.ID_INSTITUICAO = I.ID_INSTITUICAO
             WHERE CN.ID_COMPONENTE = ? AND I.ID_DOCENTE = ?`,
            [id, user.id]
        ) as any[];

        if (componentes.length === 0) {
            return sendJSON(res, 404, {
                success: false,
                message: 'Componente não encontrado ou você não tem permissão para excluí-lo'
            });
        }

        // Exclui o componente (cascade vai excluir as notas relacionadas)
        await query(
            'DELETE FROM COMPONENTE_NOTA WHERE ID_COMPONENTE = ?',
            [id]
        );

        sendJSON(res, 200, {
            success: true,
            message: 'Componente excluído com sucesso'
        });

    } catch (error: any) {
        // Trata erros de Foreign Key
        const fkError = handleForeignKeyError(error, 'componente');
        if (fkError) {
            return sendJSON(res, 400, fkError);
        }
        
        console.error('Erro ao excluir componente:', error);
        sendJSON(res, 500, {
            erro: true,
            mensagem: 'Erro interno do servidor'
        });
    }
}

// ============================================================================
// ROTAS DE NOTAS
// ============================================================================

/**
 * GET /notas?turmaId=X - Lista notas de uma turma
 */
export async function handleGetNotas(req: IncomingMessage, res: ServerResponse): Promise<void> {
    try {
        // Verifica autenticação
        const user = await authenticateToken(req);
        if (!user) {
            return sendJSON(res, 401, {
                success: false,
                message: 'Token de autenticação inválido ou ausente'
            });
        }

        // Extrai turmaId da query string
        const url = new URL(req.url || '', `http://${req.headers.host}`);
        const turmaId = url.searchParams.get('turmaId');

        if (!turmaId) {
            return sendJSON(res, 400, {
                success: false,
                message: 'turmaId é obrigatório'
            });
        }

        // Verifica se a turma pertence ao docente
        const turmas = await query(
            `SELECT T.ID_TURMA
             FROM TURMA T
             INNER JOIN DISCIPLINA D ON T.ID_DISCIPLINA = D.ID_DISCIPLINA
             INNER JOIN CURSO C ON D.ID_CURSO = C.ID_CURSO
             INNER JOIN INSTITUICAO I ON C.ID_INSTITUICAO = I.ID_INSTITUICAO
             WHERE T.ID_TURMA = ? AND I.ID_DOCENTE = ?`,
            [parseInt(turmaId), user.id]
        ) as any[];

        if (turmas.length === 0) {
            return sendJSON(res, 404, {
                success: false,
                message: 'Turma não encontrada ou você não tem permissão para acessá-la'
            });
        }

        // Busca alunos da turma
        const alunos = await query(
            `SELECT ID_ALUNO as id, RA as ra, NOME as nome
             FROM ALUNO
             WHERE ID_TURMA = ?
             ORDER BY NOME`,
            [parseInt(turmaId)]
        ) as any[];

        // Busca componentes da disciplina da turma
        const turmaInfo = await query(
            `SELECT T.ID_DISCIPLINA
             FROM TURMA T
             WHERE T.ID_TURMA = ?`,
            [parseInt(turmaId)]
        ) as any[];

        if (turmaInfo.length === 0) {
            return sendJSON(res, 404, {
                success: false,
                message: 'Turma não encontrada'
            });
        }

        const disciplinaId = turmaInfo[0].ID_DISCIPLINA;

        const componentes = await query(
            `SELECT ID_COMPONENTE as id, NOME_COMPONENTE as nome, SIGLA as sigla, PESO as peso
             FROM COMPONENTE_NOTA
             WHERE ID_DISCIPLINA = ?
             ORDER BY NOME_COMPONENTE`,
            [disciplinaId]
        ) as any[];

        // Busca notas finais da turma
        const notasFinais = await query(
            `SELECT ID_ALUNO as alunoId, NOTA_FINAL as notaFinal
             FROM NOTA_FINAL
             WHERE ID_TURMA = ?`,
            [parseInt(turmaId)]
        ) as any[];

        // Cria mapa de notas finais
        const notasFinaisMap: { [key: number]: number } = {};
        notasFinais.forEach((nf: any) => {
            notasFinaisMap[nf.alunoId] = parseFloat(nf.notaFinal) || 0;
        });

        // Busca todas as notas
        const notas = await query(
            `SELECT 
                N.ID_ALUNO as alunoId,
                N.ID_COMPONENTE as componenteId,
                N.VALOR as valor
             FROM NOTA N
             INNER JOIN ALUNO A ON N.ID_ALUNO = A.ID_ALUNO
             WHERE A.ID_TURMA = ?`,
            [parseInt(turmaId)]
        ) as any[];

        // Organiza as notas por aluno e componente
        const notasOrganizadas: any = {};
        alunos.forEach((aluno: any) => {
            notasOrganizadas[aluno.id] = {};
            componentes.forEach((comp: any) => {
                notasOrganizadas[aluno.id][comp.id] = 0;
            });
        });

        notas.forEach((nota: any) => {
            if (notasOrganizadas[nota.alunoId]) {
                notasOrganizadas[nota.alunoId][nota.componenteId] = parseFloat(nota.valor);
            }
        });

        sendJSON(res, 200, {
            success: true,
            data: {
                alunos: alunos,
                componentes: componentes,
                notas: notasOrganizadas,
                notasFinais: notasFinaisMap
            }
        });

    } catch (error: any) {
        console.error('Erro ao buscar notas:', error);
        sendJSON(res, 500, {
            success: false,
            message: 'Erro interno do servidor'
        });
    }
}

/**
 * Função auxiliar para calcular e salvar nota final de um aluno
 */
async function calcularESalvarNotaFinal(alunoId: number, turmaId: number, tipoMedia: string): Promise<number> {
    // Busca todos os componentes da disciplina da turma
    const turmaInfo = await query(
        `SELECT T.ID_DISCIPLINA
         FROM TURMA T
         WHERE T.ID_TURMA = ?`,
        [turmaId]
    ) as any[];

    if (turmaInfo.length === 0) {
        return 0;
    }

    const disciplinaId = turmaInfo[0].ID_DISCIPLINA;

    // Busca componentes
    const componentes = await query(
        `SELECT ID_COMPONENTE as id, PESO as peso
         FROM COMPONENTE_NOTA
         WHERE ID_DISCIPLINA = ?`,
        [disciplinaId]
    ) as any[];

    if (componentes.length === 0) {
        // Se não tem componentes, nota final é 0
        await query(
            `INSERT INTO NOTA_FINAL (ID_ALUNO, ID_TURMA, NOTA_FINAL)
             VALUES (?, ?, 0)
             ON DUPLICATE KEY UPDATE NOTA_FINAL = 0, DATA_CALCULO = CURRENT_TIMESTAMP`,
            [alunoId, turmaId]
        );
        return 0;
    }

    // Busca todas as notas do aluno para esses componentes
    const notas = await query(
        `SELECT ID_COMPONENTE as componenteId, VALOR as valor
         FROM NOTA
         WHERE ID_ALUNO = ? AND ID_COMPONENTE IN (${componentes.map(() => '?').join(',')})`,
        [alunoId, ...componentes.map((c: any) => c.id)]
    ) as any[];

    // Cria mapa de notas
    const notasMap: { [key: number]: number } = {};
    notas.forEach((nota: any) => {
        notasMap[nota.componenteId] = parseFloat(nota.valor) || 0;
    });

    let notaFinal = 0;

    if (tipoMedia === 'simples') {
        // Média Simples: soma todas as notas / quantidade de componentes
        let soma = 0;
        componentes.forEach((comp: any) => {
            soma += notasMap[comp.id] || 0;
        });
        notaFinal = componentes.length > 0 ? soma / componentes.length : 0;
    } else {
        // Média Ponderada
        let somaPonderada = 0;
        let somaPesos = 0;
        componentes.forEach((comp: any) => {
            const peso = parseFloat(comp.peso) || 0;
            const valor = notasMap[comp.id] || 0;
            if (peso > 0) {
                somaPonderada += valor * peso;
                somaPesos += peso;
            }
        });
        notaFinal = somaPesos > 0 ? somaPonderada / somaPesos : 0;
    }

    // Limita entre 0 e 10
    notaFinal = Math.max(0, Math.min(10, notaFinal));

    // Salva ou atualiza nota final
    await query(
        `INSERT INTO NOTA_FINAL (ID_ALUNO, ID_TURMA, NOTA_FINAL)
         VALUES (?, ?, ?)
         ON DUPLICATE KEY UPDATE NOTA_FINAL = ?, DATA_CALCULO = CURRENT_TIMESTAMP`,
        [alunoId, turmaId, notaFinal, notaFinal]
    );

    return notaFinal;
}

/**
 * POST /notas/bulk - Salva múltiplas notas de uma vez
 */
export async function handleBulkNotas(req: IncomingMessage, res: ServerResponse): Promise<void> {
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
        const { notas, tipoMedia } = body;

        if (!Array.isArray(notas)) {
            return sendJSON(res, 400, {
                success: false,
                message: 'notas deve ser um array'
            });
        }

        // Processa cada nota
        const resultados = [];
        for (const nota of notas) {
            const { alunoId, componenteId, valor } = nota;

            if (!alunoId || !componenteId || valor === undefined || valor === null) {
                continue;
            }

            const valorNum = parseFloat(valor);
            if (isNaN(valorNum) || valorNum < 0 || valorNum > 10) {
                continue;
            }

            // Aceita valor 0 (nota zerada)
            // Não pula se valor for 0

            try {
                // Verifica permissões (aluno e componente)
                const alunos = await query(
                    `SELECT A.ID_ALUNO
                     FROM ALUNO A
                     INNER JOIN TURMA T ON A.ID_TURMA = T.ID_TURMA
                     INNER JOIN DISCIPLINA D ON T.ID_DISCIPLINA = D.ID_DISCIPLINA
                     INNER JOIN CURSO C ON D.ID_CURSO = C.ID_CURSO
                     INNER JOIN INSTITUICAO I ON C.ID_INSTITUICAO = I.ID_INSTITUICAO
                     WHERE A.ID_ALUNO = ? AND I.ID_DOCENTE = ?`,
                    [parseInt(alunoId), user.id]
                ) as any[];

                if (alunos.length === 0) continue;

                const componentes = await query(
                    `SELECT CN.ID_COMPONENTE
                     FROM COMPONENTE_NOTA CN
                     INNER JOIN DISCIPLINA D ON CN.ID_DISCIPLINA = D.ID_DISCIPLINA
                     INNER JOIN CURSO C ON D.ID_CURSO = C.ID_CURSO
                     INNER JOIN INSTITUICAO I ON C.ID_INSTITUICAO = I.ID_INSTITUICAO
                     WHERE CN.ID_COMPONENTE = ? AND I.ID_DOCENTE = ?`,
                    [parseInt(componenteId), user.id]
                ) as any[];

                if (componentes.length === 0) continue;

                // Verifica se a nota já existe
                const notasExistentes = await query(
                    'SELECT ID_NOTA FROM NOTA WHERE ID_ALUNO = ? AND ID_COMPONENTE = ?',
                    [parseInt(alunoId), parseInt(componenteId)]
                ) as any[];

                if (notasExistentes.length > 0) {
                    await query(
                        'UPDATE NOTA SET VALOR = ? WHERE ID_ALUNO = ? AND ID_COMPONENTE = ?',
                        [valorNum, parseInt(alunoId), parseInt(componenteId)]
                    );
                } else {
                    await query(
                        'INSERT INTO NOTA (ID_ALUNO, ID_COMPONENTE, VALOR) VALUES (?, ?, ?)',
                        [parseInt(alunoId), parseInt(componenteId), valorNum]
                    );
                }

                resultados.push({ alunoId: parseInt(alunoId), componenteId: parseInt(componenteId), valor: valorNum });
            } catch (error) {
                console.error('Erro ao processar nota:', error);
            }
        }

        // Busca turmaId do primeiro aluno (todos devem ser da mesma turma)
        let turmaId: number | null = null;
        if (resultados.length > 0) {
            const primeiroAluno = resultados[0].alunoId;
            const alunoInfo = await query(
                'SELECT ID_TURMA FROM ALUNO WHERE ID_ALUNO = ?',
                [primeiroAluno]
            ) as any[];
            if (alunoInfo.length > 0) {
                turmaId = alunoInfo[0].ID_TURMA;
            }
        }

        // Tipo de média padrão: simples
        const tipoMediaCalculo = tipoMedia || 'simples';

        // Recalcula nota final para TODOS os alunos da turma (não apenas os que tiveram notas alteradas)
        // Isso garante que se um novo componente foi adicionado, todos os alunos terão nota final recalculada
        const notasFinaisCalculadas: { [key: number]: number } = {};
        if (turmaId) {
            // Busca todos os alunos da turma
            const todosAlunos = await query(
                'SELECT ID_ALUNO FROM ALUNO WHERE ID_TURMA = ?',
                [turmaId]
            ) as any[];

            // Recalcula nota final para cada aluno da turma
            for (const aluno of todosAlunos) {
                try {
                    const notaFinal = await calcularESalvarNotaFinal(aluno.ID_ALUNO, turmaId, tipoMediaCalculo);
                    notasFinaisCalculadas[aluno.ID_ALUNO] = notaFinal;
                } catch (error) {
                    console.error(`Erro ao calcular nota final para aluno ${aluno.ID_ALUNO}:`, error);
                }
            }
        }

        sendJSON(res, 200, {
            success: true,
            message: `${resultados.length} nota(s) salva(s) com sucesso`,
            data: {
                notas: resultados,
                notasFinais: notasFinaisCalculadas
            }
        });

    } catch (error: any) {
        console.error('Erro ao salvar notas em lote:', error);
        sendJSON(res, 500, {
            success: false,
            message: 'Erro interno do servidor'
        });
    }
}

