import express from 'express';
import crypto from 'crypto';
import dotenv from "dotenv";

dotenv.config()

const app = express();
app.use(express.json());

const SECRET_KEY = process.env.SECRET_KEY;
const ADMIN_TOKEN = process.env.ADMIN_TOKEN;

function generateSHA256(data) {
    return crypto.createHash('sha256').update(data).digest('hex');
}

// --- BANCO DE DADOS SIMULADO  ---
const simulatedUsersDB = [
    { 
        user_code: "10000001", 
        nome: "Lucas Fernando", 
        senha_hash: generateSHA256("1234"),
        hora_inicio: "08:00", 
        hora_fim: "18:00" 
    },
    { 
        user_code: "20000002", 
        nome: "Kaina Magdiel", 
        senha_hash: generateSHA256("5678"),
        hora_inicio: "00:00", 
        hora_fim: "23:59" 
    },
    { 
        user_code: "30000003", 
        nome: "Thiago Lo", 
        senha_hash: generateSHA256("9000"),
        hora_inicio: "22:00", 
        hora_fim: "06:00" 
    }
];


function getEsp32UserList() {
    return simulatedUsersDB.map(u => ({
        user_code: u.user_code,
        senha_hash: u.senha_hash,
        hora_inicio: u.hora_inicio,
        hora_fim: u.hora_fim
    }));
}

function checkAdmin(req, res, next) {
  const token = req.headers['x-admin-token'];
  if (!token || token !== ADMIN_TOKEN) {
    return res.status(403).json({ error: 'Acesso negado: token inválido' });
  }
  next();
}

app.get("/users/all", checkAdmin, (req, res) => {
    res.json(simulatedUsersDB);
});


app.get('/users', (req, res) => {
    try {
        const usersListForESP32 = getEsp32UserList();
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
  console.log('Server running with simulated JSON on port 3000');
});