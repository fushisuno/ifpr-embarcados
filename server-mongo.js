import express from 'express';
import swaggerJsdoc from 'swagger-jsdoc';
import swaggerUi from 'swagger-ui-express';
import crypto from 'crypto';
import { MongoClient } from 'mongodb';
import dotenv from 'dotenv';

dotenv.config();

const app = express();

const swaggerOptions = {
  swaggerDefinition: {
    openapi: '3.0.0',
    info: {
      title: 'API de Gestão de Usuários',
      description: 'API para criar, consultar usuários e registrar logs',
      version: '1.0.0',
    },
    servers: [
      {
        url: 'http://localhost:3000',
      },
    ],
  },
  apis: ['./server-mongo.js'],
};

const swaggerDocs = swaggerJsdoc(swaggerOptions);
app.use('/docs', swaggerUi.serve, swaggerUi.setup(swaggerDocs));

app.use(express.json());

const MONGO_URI = process.env.MONGO_URI;
const client = new MongoClient(MONGO_URI);

await client.connect();
const db = client.db('mongo');
const usersCollection = db.collection('users');
const logsCollection = db.collection('logs');

const SECRET_KEY = process.env.SECRET_KEY;
const ADMIN_TOKEN = process.env.ADMIN_TOKEN;

function generateSHA256(data) {
  return crypto.createHash('sha256').update(data).digest('hex');
}

function checkAdmin(req, res, next) {
  const token = req.headers['x-admin-token'];
  if (!token || token !== ADMIN_TOKEN) {
    return res.status(403).json({ error: 'Acesso negado: token inválido' });
  }
  next();
}

async function getEsp32UserList() {
  const usersArray = await usersCollection.find({}).toArray();
  return usersArray.map(u => ({
    user_code: u.user_code,
    senha_hash: generateSHA256(u.senha),
    hora_inicio: u.hora_inicio,
    hora_fim: u.hora_fim
  }));
}

/**
 * @swagger
 * /users:
 *   post:
 *     summary: Criar um novo usuário
 *     description: Cria um novo usuário com os dados fornecidos
 *     tags: [Users]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               nome:
 *                 type: string
 *               senha:
 *                 type: string
 *               hora_inicio:
 *                 type: string
 *               hora_fim:
 *                 type: string
 *     responses:
 *       200:
 *         description: Usuário criado com sucesso
 *       400:
 *         description: Dados inválidos
 *       500:
 *         description: Erro interno do servidor
 */
app.post("/users", checkAdmin, async (req, res) => {
  try {
    const { nome, senha, hora_inicio, hora_fim } = req.body;

    if (!nome || !senha || !hora_inicio || !hora_fim) {
      return res.status(400).json({ error: "Nome, senha, hora_inicio e hora_fim são obrigatórios" });
    }

    if (!/^\d{4}$/.test(senha)) {
      return res.status(400).json({ error: "A senha deve conter exatamente 4 números." });
    }

    const userCode = Math.floor(Math.random() * 100000000).toString().padStart(8, '0');

    const user = {
      user_code: userCode,
      nome,
      senha,
      hora_inicio,
      hora_fim
    };

    await usersCollection.insertOne(user);
    res.json({ user });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Erro ao criar usuário" });
  }
});

/**
 * @swagger
 * /users/all:
 *   get:
 *     summary: Lista todos os usuários
 *     description: Retorna uma lista com todos os usuários cadastrados
 *     tags: [Users]
 *     responses:
 *       200:
 *         description: Lista de usuários
 *       500:
 *         description: Erro interno do servidor
 */
app.get("/users/all", checkAdmin, async (req, res) => {
  try {
    const usersArray = await usersCollection.find({}).toArray();
    res.json(usersArray);
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Erro ao buscar usuários" });
  }
});

/**
 * @swagger
 * /users:
 *   get:
 *     summary: Obter lista de usuários para ESP32
 *     description: Retorna a lista de usuários com um HMAC para validar a integridade dos dados
 *     tags: [Users]
 *     responses:
 *       200:
 *         description: Lista de usuários com HMAC
 *       500:
 *         description: Erro interno ao gerar lista de usuários
 */
app.get('/users', async (req, res) => {
  try {
    const usersListForESP32 = await getEsp32UserList();
    const stringToHash = JSON.stringify(usersListForESP32);

    const hmac = crypto
      .createHmac("sha256", SECRET_KEY)
      .update(stringToHash)
      .digest("hex");

    res.json({ list: usersListForESP32, hmac });
  } catch (e) {
    console.error("Erro ao gerar lista para ESP32:", e);
    res.status(500).json({ error: 'Erro interno ao buscar lista de usuários' });
  }
});

/**
 * @swagger
 * /logs:
 *   post:
 *     summary: Salvar logs
 *     description: Recebe uma lista de logs e valida com o HMAC
 *     tags: [Logs]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               logs:
 *                 type: array
 *                 items:
 *                   type: object
 *               hmac:
 *                 type: string
 *     responses:
 *       200:
 *         description: Logs salvos com sucesso
 *       400:
 *         description: HMAC inválido
 *       500:
 *         description: Erro interno ao salvar logs
 */
app.post('/logs', async (req, res) => {
  try {
    const { logs, hmac } = req.body;

    const computed = crypto.createHmac('sha256', SECRET_KEY)
      .update(JSON.stringify(logs))
      .digest('hex');

    if (computed !== hmac) {
      return res.status(400).json({ error: 'HMAC inválido' });
    }

    await logsCollection.insertMany(logs);
    res.json({ message: 'Logs salvos com sucesso' });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Erro ao salvar logs' });
  }
});

/**
 * @swagger
 * /logs:
 *   get:
 *     summary: Listar logs
 *     description: Retorna todos os logs armazenados no banco
 *     tags: [Logs]
 *     responses:
 *       200:
 *         description: Lista de logs
 *       500:
 *         description: Erro interno ao buscar logs
 */
app.get("/logs", checkAdmin, async (req, res) => {
  try {
    const logs = await logsCollection.find({}).sort({ timestamp: -1 }).toArray();
    res.json(logs);
  } catch (e) {
    console.error("Erro ao buscar logs:", e);
    res.status(500).json({ error: "Erro interno ao buscar logs" });
  }
});


app.listen(3000, () => {
  console.log('Server running with MongoDB on port 3000');
});
