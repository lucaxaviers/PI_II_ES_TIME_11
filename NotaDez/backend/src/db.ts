/* Autores do arquivo: Todos os integrantes */

import mysql from 'mysql2/promise';
import dotenv from 'dotenv';

dotenv.config();

const dbConfig = {
    
    host: process.env.DB_HOST || '127.0.0.1',

    port: parseInt(process.env.DB_PORT || '3306'),

    user: process.env.DB_USER || 'root',

    password: process.env.DB_PASSWORD || '',

    database: process.env.DB_NAME || 'notadez',

    waitForConnections: true,
    connectionLimit: 10,  
    queueLimit: 0
};

export const pool = mysql.createPool(dbConfig);

export async function testConnection(): Promise<void> {
    try {
        const connection = await pool.getConnection();
        console.log('✅ Teste de conexão com MySQL: OK');
        connection.release();
    } catch (error: any) {
        console.error('❌ Erro ao conectar com MySQL:', error.message);
        throw error;
    }
}

export async function query(sql: string, params?: any[]): Promise<any> {
    try {
        const [results] = await pool.execute(sql, params);
        return results;
    } catch (error: any) {
        console.error('❌ Erro ao executar query SQL:', error.message);
        console.error('   SQL:', sql);
        if (params && params.length > 0) {
            console.error('   Parâmetros:', params);
        }
        throw error;
    }
}

