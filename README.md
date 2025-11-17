# 📚 NotaDez - Sistema de Gestão de Notas

E aí! 👋 Bem-vindo ao **NotaDez**! 

Basicamente, criamos um sistema pra ajudar professores a organizarem as notas dos alunos sem muito estresse. É tipo um caderninho digital, mas melhor e mais organizado.

## 📋 O que é isso?

O NotaDez é um sistema web que deixa o professor:

- 🏫 Cadastrar a instituição e cursos
- 📖 Organizar as disciplinas
- 👥 Criar turmas
- 👨‍🎓 Adicionar alunos
- 📊 Lançar notas e calcular médias automaticamente
- 📈 Ver como os alunos estão indo

Resumindo: tudo que você precisa pra gerenciar notas de forma simples e sem complicação. A interface é bem fácil de usar, então qualquer professor consegue navegar de boa.

## 👥 Quem fez? - **TIME_11** - Projeto Integrador II

**Alunos:**

Gustavo Antonio Mariano - 25009767

Leonardo Gambaroni Alves - 25003494

Lucas Rodrigues Xavier - 25000508

## 🚀 Como fazer funcionar

Antes de tudo, você precisa instalar umas coisinhas no seu computador:

### O que você precisa

- **Node.js** (versão 16 ou mais) - [Baixa aqui](https://nodejs.org/)
- **MySQL** (versão 8.0 ou mais) - [Baixa aqui](https://dev.mysql.com/downloads/mysql/)
- Um editor de código qualquer (a gente usa o VS Code, mas pode ser qualquer um)

### Passo 1: Baixar o código

Abra o terminal (ou Prompt de Comando se tiver Windows) e rode:

```bash
git clone https://github.com/lucaxaviers/PI_II_ES_TIME_11.git
cd PI_II_ES_TIME_11
```

### Passo 2: Preparar o banco de dados

1. Abre o MySQL Workbench (ou qualquer programa que você use pra MySQL)
2. Cria um banco de dados novo (ou usa um que você já tem)
3. Abre o arquivo `NotaDez/scripts/notadez.sql`
4. Roda o script SQL inteiro - ele cria todas as tabelas que a gente precisa

O script já cria tudo automaticamente

### Passo 3: Configurar o backend

1. Entra na pasta do backend:

```bash
cd NotaDez/backend
```

2. Instala as dependências (pode demorar um pouquinho):

```bash
npm install
```

3. Login do banco
   
   Abra o arquivo `NotaDez/backend/src/db.ts` e edita essas linhas com seus dados do MySQL:

   ```typescript
   const dbConfig = {
       host: process.env.DB_HOST || '127.0.0.1',
       port: parseInt(process.env.DB_PORT || '3306'),
       user: process.env.DB_USER || 'root',  // muda aqui pro seu usuário
       password: process.env.DB_PASSWORD || '',  // muda aqui pra sua senha
       database: process.env.DB_NAME || 'notadez',
       ...
   };
   ```

### Passo 4: Compilar o código

O backend é em TypeScript, então precisa compilar pra JavaScript primeiro:

```bash
npm run build
```

### Passo 5: Rodar o servidor

Pra rodar em modo de desenvolvimento (que é mais fácil pra testar):

```bash
npm run dev
```

Ou se já compilou antes:

```bash
npm start
```

Você vai ver uma mensagem dizendo que o servidor tá rodando na porta 3000. Se aparecer, tá tudo certo! ✅

### Passo 6: Abrir no navegador

1. Abra o live server no VScode
2. Va até a pasta `NotaDez` no seu computador
3. Abre o arquivo `login.html`

## 🛠️ O que a gente usou

### Frontend
- **HTML5** - Estrutura das páginas
- **CSS3** - Pra deixar bonito
- **JavaScript** - Funcionalidades
- **Bootstrap 5** - Pra layout responsivo
- **Bootstrap Icons** - Ícones

### Backend
- **Node.js** - Roda o servidor
- **TypeScript** - Linguagem que usamos
- **MySQL** - Banco de dados
- **JWT** - Autenticação
- **bcrypt** - Criptografa as senhas

## 📝 Depois que instalar, como usar?

1. **Criar conta:** Vai no cadastro e cria seu usuário de professor
2. **Fazer login:** Entra com suas credenciais
3. **Cadastrar instituição:** Começa cadastrando sua instituição
4. **Criar curso:** Adiciona os cursos que tem
5. **Adicionar disciplinas:** Registra as disciplinas de cada curso
6. **Criar turmas:** Organiza os alunos em turmas
7. **Cadastrar alunos:** Adiciona os estudantes nas turmas
8. **Definir componentes:** Configura os tipos de avaliação (provas, trabalhos, etc.)
9. **Lançar notas:** Começa a lançar as notas dos alunos

É nessa ordem mesmo! Vai passo a passo que funciona melhor.

## ⚙️ Algumas configurações importantes

### Porta do servidor

Por padrão, o servidor roda na porta 3000. Se precisar mudar:

1. Edita o arquivo `.env` na pasta `backend`
2. Muda a variável `PORT`
3. Reinicia o servidor

### Banco de dados

O sistema usa MySQL. Confirma que:
- O MySQL tá rodando
- As credenciais no `.env` tão certas
- O banco foi criado e o script SQL rodou

### Segurança

Pra testes locais, já tá configurado e funciona tranquilo. Se for colocar em produção, aí precisa ajustar umas coisinhas de segurança no `routes.ts`.

## 🐛 Problemas? Aqui tem algumas soluções

### Erro ao conectar no banco
- Confere se o MySQL tá rodando
- Verifica se usuário e senha no `.env` tão certos
- Certifica que o banco `notadez` existe

### Porta 3000 já em uso
- Muda a porta no arquivo `.env`
- Ou fecha o programa que tá usando a porta 3000

### Páginas não carregam
- Confere se o servidor backend tá rodando
- Verifica se tá abrindo pelo protocolo certo (http:// ou file://)
- Dá uma olhada no console do navegador pra ver se tem erros

