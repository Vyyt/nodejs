const express = require('express');
const mysql = require('mysql2');
const Joi = require('joi');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const { authenticate } = require('./middleware');
require('dotenv').config();

const server = express();
server.use(express.json());
server.use(cors());

const mysqlConfig = {
  host: 'localhost',
  user: 'root',
  password: process.env.DB_PASS,
  database: 'reactdb',
};

const loginSchema = Joi.object({
  email: Joi.string().email().trim().lowercase()
    .required(),
  password: Joi.string().required(),
});

const clientRegistSchema = Joi.object({
  full_name: Joi.string().trim(),
  email: Joi.string().email().trim().lowercase(),
  age: Joi.string(),
});

const dbPool = mysql.createPool(mysqlConfig).promise();

server.get('/', authenticate, (req, res) => {
  res.status(200).send({ message: 'Authorized' });
});

server.post('/login', async (req, res) => {
  let payload = req.body;
console.log(payload)
  try {
    payload = await loginSchema.validateAsync(payload);
  } catch (error) {
    return res.status(400).send({ error: 'All fields are required' });
  }

  try {
    const [data] = await dbPool.execute(
      `
      SELECT * FROM login
      WHERE email = ?`,
      [payload.email],
    );

    if (!data.length) {
      return res.status(400).send({ error: 'Email or password did not match' });
    }

    const isPasswordMatching = await bcrypt.compare(
      payload.password,
      data[0].password,
    );

    if (isPasswordMatching) {
      const token = jwt.sign(
        {
          email: data[0].email,
          id: data[0].id,
        },
        process.env.JWT_SECRET,
      );
      return res.status(200).send({ token });
    }

    return res.status(400).send({ error: 'Email or password did not match' });
  } catch (error) {
    return res.status(500).end();
  }
});

server.post('/register', async (req, res) => {
  let payload = req.body;
  console.log(payload)
  try {
    payload = await clientRegistSchema.validateAsync(payload);
  } catch (error) {
    return res.status(400).send({ error: 'All fields are required' });
  }
  try {
    await dbPool.execute(
      `
        INSERT INTO clients (full_name, email, age)
        VALUES (?, ?, ?)
        `,
      [payload.full_name, payload.email, payload.age],
    );

    return res.status(201).send({ message: 'Registration successful' });
  } catch (error) {
    return res.status(500).end();
  }
});

server.get('/clients', async (req, res) => {
  try {
    const [clients] = await dbPool.execute('SELECT * FROM clients');
    return res.json(clients);
  } catch (error) {
    return res.status(500).end();
  }
});

server.listen(process.env.PORT, () => console.log(`Server is running on port ${process.env.PORT}`));
