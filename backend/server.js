// Importa os módulos necessários
const express = require('express'); // Framework web para Node.js
const mysql = require('mysql2'); // Driver MySQL
const cors = require('cors'); // Middleware para CORS
const bcrypt = require('bcrypt'); // Para hash de senhas

// Cria uma instância do aplicativo Express
const app = express();

// Define a porta em que o servidor irá escutar
const port = 3000; // Altere para 3000

// Middleware para permitir o envio de JSON
app.use(express.json());
app.use(cors()); // Habilitar CORS

// Configuração da conexão com o MySQL
const connection = mysql.createConnection({
    host: 'localhost',
    user: 'root', // Substitua pelo seu usuário do MySQL
    password: '', // Substitua pela sua senha do MySQL
    database: 'app_voyago', // Substitua pelo nome do seu banco de dados
});

// Conecta-se ao banco de dados
connection.connect((err) => {
    if (err) {
        console.error('Erro ao conectar: ' + err.stack);
        return;
    }
    console.log('Conectado ao banco de dados como id ' + connection.threadId);
});

// Rota para registro de usuários
app.post('/register', (req, res) => {
    const { email, nome, telefone, senha } = req.body;

    // Verifica se a senha não está vazia
    if (!senha) {
        return res.status(400).json({ error: "A senha não pode estar vazia." });
    }

    // Verifica se o e-mail já está cadastrado
    const sql_check_email = "SELECT COUNT(*) AS total FROM usuarios WHERE email = ?";
    connection.query(sql_check_email, [email], (err, results) => {
        if (err) {
            return res.status(500).json({ error: "Erro ao executar a consulta: " + err.message });
        }

        if (results[0].total > 0) {
            // E-mail já cadastrado
            return res.status(400).json({ error: "Este e-mail já está cadastrado." });
        } else {
            // Hash da senha
            const senha_hash = bcrypt.hashSync(senha, 10); // O número 10 é o "salt rounds"

            // Insere os dados na tabela de usuários
            const sql = "INSERT INTO usuarios (email, nome, telefone, senha) VALUES (?, ?, ?, ?)";
            connection.query(sql, [email, nome, telefone, senha_hash], (err, results) => {
                if (err) {
                    return res.status(500).json({ error: "Erro ao executar a consulta: " + err.message });
                }
                
                // Verifica se a inserção foi bem-sucedida
                if (results.affectedRows > 0) {
                    return res.status(201).json({ success: "Usuário cadastrado com sucesso! Faça Login!" });
                } else {
                    return res.status(500).json({ error: "Erro ao cadastrar usuário." });
                }
            });
        }
    });
});

// Rota para login de usuários
app.post('/login', (req, res) => {
    const { email, senha } = req.body;

    // Verifica se o e-mail e a senha não estão vazios
    if (!email || !senha) {
        return res.status(400).json({ error: "Email e senha são obrigatórios." });
    }

    // Consulta o usuário no banco de dados
    const sql = "SELECT * FROM usuarios WHERE email = ?";
    connection.query(sql, [email], (err, results) => {
        if (err) {
            return res.status(500).json({ error: "Erro ao executar a consulta: " + err.message });
        }

        // Verifica se o usuário existe
        if (results.length === 0) {
            return res.status(400).json({ error: "Email ou senha inválidos." });
        }

        // Verifica a senha
        const usuario = results[0];
        const senhaValida = bcrypt.compareSync(senha, usuario.senha);

        if (!senhaValida) {
            return res.status(400).json({ error: "Email ou senha inválidos." });
        }

        // Login bem-sucedido
        return res.status(200).json({ success: "Login realizado com sucesso!" });
    });
});

// Iniciar o servidor
app.listen(port, () => {
    console.log(`Servidor rodando na porta ${port}`);
});
