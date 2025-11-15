import mysql from 'mysql2/promise';
import dotenv from 'dotenv';

// Carrega variáveis de ambiente do arquivo .env
dotenv.config();

const dbConfig = {
    // Endereço do servidor MySQL 
    host: process.env.DB_HOST || '127.0.0.1',
    
    // Porta do MySQL (geralmente 3306)
    // Verifique se sua instalação usa outra porta
    port: parseInt(process.env.DB_PORT || '3306'),
    
    // Usuário do MySQL (geralmente 'root' ou um usuário criado)
    user: process.env.DB_USER || 'root',
    
    // Senha do MySQL
    // Deixe vazio se não tiver senha configurada
    password: process.env.DB_PASSWORD || '',
    
    // Nome do banco de dados criado no MySQL
    // Deve ser o mesmo nome usado em: CREATE DATABASE notadez;
    database: process.env.DB_NAME || 'notadez',
    
    // Configurações do pool de conexões
    waitForConnections: true,
    connectionLimit: 10,  // Máximo de conexões simultâneas
    queueLimit: 0
};

/**
 * Pool de conexões MySQL
 */
export const pool = mysql.createPool(dbConfig);

/**
 * Testa a conexão com o banco de dados
 */
export async function testConnection(): Promise<void> {
    try {
        const connection = await pool.getConnection();
        console.log('✅ Conexão com MySQL estabelecida com sucesso!');
        connection.release();
    } catch (error) {
        console.error('❌ Erro ao conectar com MySQL:', error);
        throw error;
    }
}

/**
 * Executa uma query SQL
 * @param sql - Query SQL a ser executada
 * @param params - Parâmetros da query (opcional)
 * @returns Resultado da query
 */
export async function query(sql: string, params?: any[]): Promise<any> {
    try {
        const [results] = await pool.execute(sql, params);
        return results;
    } catch (error) {
        console.error('Erro ao executar query:', error);
        throw error;
    }
}

