const express = require('express');
const cors = require('cors');
const axios = require('axios');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const port = process.env.PORT || 3000;
require('dotenv').config();

const app = express();
app.use(cors({
    origin: ['http://localhost:3000', 'https://calculadora-frontend.onrender.com'],
    methods: ['GET', 'POST', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization'],
    credentials: true
}));
app.use(express.json());

// Usuarios (en producción deberían estar en una base de datos)
const users = [
  {
    id: 1,
    username: process.env.ADMIN_USER || 'admin',
    passwordHash: bcrypt.hashSync(process.env.ADMIN_PASSWORD || 'admin123', 10),
    role: 'admin'
  },
  {
    id: 2,
    username: process.env.ANALYST_USER || 'analista',
    passwordHash: bcrypt.hashSync(process.env.ANALYST_PASSWORD || 'analista123', 10),
    role: 'analyst'
  }
];

// Middleware de autenticación
const authenticateJWT = (req, res, next) => {
  const authHeader = req.headers.authorization;
  
  if (authHeader) {
    const token = authHeader.split(' ')[1];
    
    jwt.verify(token, process.env.JWT_SECRET || 'your-secret-key', (err, user) => {
      if (err) {
        return res.sendStatus(403);
      }
      
      req.user = user;
      next();
    });
  } else {
    res.sendStatus(401);
  }
};

// Ruta de login
app.post('/login', (req, res) => {
  const { username, password } = req.body;
  
  const user = users.find(u => u.username === username);
  if (!user) {
    return res.status(401).json({ error: 'Usuario no encontrado' });
  }
  
  if (!bcrypt.compareSync(password, user.passwordHash)) {
    return res.status(401).json({ error: 'Contraseña incorrecta' });
  }
  
  const token = jwt.sign(
    { userId: user.id, username: user.username, role: user.role },
    process.env.JWT_SECRET || 'your-secret-key',
    { expiresIn: '1h' }
  );
  
  res.json({ token });
});

// Proteger la ruta del proxy con autenticación
app.post('/proxy', authenticateJWT, async (req, res) => {
  try {
    const response = await axios.post('https://api-test.avalburo.com/services/V8/getWebService', req.body, {
      headers: {
        'Authorization': 'Basic ' + Buffer.from('WSTEST-MAXC:YC^1#I8P@V').toString('base64'),
        'Content-Type': 'application/json',
      }
    });
    res.json(response.data);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Ruta protegida de ejemplo
app.get('/protected', authenticateJWT, (req, res) => {
  res.json({ message: `Hola ${req.user.username}, tienes rol ${req.user.role}` });
});

app.listen(port, () => {
    console.log(`Proxy server running at http://localhost:${port}`);
});