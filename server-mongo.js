
import express from 'express';
import crypto from 'crypto';
import { MongoClient } from 'mongodb';
import dotenv from "dotenv";

dotenv.config()

const app = express();
app.use(express.json());

const MONGO_URI = process.env.MONGO_URI
const client = new MongoClient(MONGO_URI);

await client.connect();
const db = client.db('mongo');
const usersCollection = db.collection('users');
const logsCollection = db.collection('logs');

const SECRET_KEY = process.env.SECRET_KEY;

function generateNumericId(length = 8) {
  let code = '';
  for (let i = 0; i < length; i++) {
    code += Math.floor(Math.random() * 10);
  }
  return code;
}

function checkAdmin(req, res, next) {
  const token = req.headers['x-admin-token'];
  if (!token || token !== (process.env.ADMIN_TOKEN)) {
    return res.status(403).json({ error: 'Acesso negado: token inválido' });
  }
  next();
}

app.post("/users", checkAdmin, async (req, res) => {
  try {
    const { nome, senha } = req.body;

    if (!nome || !senha) {
      return res.status(400).json({ error: "Nome e senha são obrigatórios" });
    }

    const code = generateNumericId();

    const user = { user_code: code, nome, senha };
    await usersCollection.insertOne(user);

    res.json({ user });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Erro ao criar usuário" });
  }
});



app.get('/users', async (req, res) => {
  try {
    const usersArray = await usersCollection.find({}).toArray();
    const userCodes = usersArray.map((u) => u.user_code);

    const hmac = crypto
      .createHmac("sha256", SECRET_KEY)
      .update(JSON.stringify(userCodes))
      .digest("hex");

    res.json({ list: usersArray, hmac });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Erro ao buscar usuários permitidos' });
  }
});

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

app.listen(3000, () => {
  console.log('Server running with MongoDB on port 3000');
});
