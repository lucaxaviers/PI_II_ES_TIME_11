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
        console.error('Erro no registro:', error);
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
        console.error('Erro no login:', error);
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
        console.error('Erro no forgot-password:', error);
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
        console.error('Erro ao listar instituições:', error);
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
        console.error('Erro ao criar instituição:', error);
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
        console.error('Erro ao atualizar instituição:', error);
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
        console.error('Erro ao excluir instituição:', error);
        sendJSON(res, 500, {
            success: false,
            message: 'Erro interno do servidor'
        });
    }
}

