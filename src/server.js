const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');
const multer = require('multer');
const CryptoJS = require('crypto-js');
const serverless = require('serverless-http');
const db = require('./db');
require('dotenv').config();

const app = express();

// Middlewares
app.use(cors({
    origin: '*', // Permitir cualquier origen (necesario para repos separados)
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization']
}));
app.use(bodyParser.json({ limit: '10mb' }));
app.use(bodyParser.urlencoded({ extended: true, limit: '10mb' }));

// Configuración de Multer EN MEMORIA (vital para Netlify/Cloud)
const storage = multer.memoryStorage();
const upload = multer({ storage });

// --- RUTAS ---

app.get('/api/health', async (req, res) => {
    try {
        await db.query('SELECT NOW()');
        res.json({ status: 'ok', message: 'Servidor Serverless y DB conectados' });
    } catch (err) {
        res.status(500).json({ status: 'error', message: err.message });
    }
});

app.post('/api/companies', async (req, res) => {
    const { monday_account_id, business_name, cuit, iva_condition, default_point_of_sale, domicilio, fecha_inicio } = req.body;
    try {
        const query = `
            INSERT INTO companies (monday_account_id, business_name, cuit, iva_condition, default_point_of_sale, address, start_date)
            VALUES ($1, $2, $3, $4, $5, $6, $7)
            ON CONFLICT (monday_account_id) 
            DO UPDATE SET 
                business_name = EXCLUDED.business_name,
                cuit = EXCLUDED.cuit,
                iva_condition = EXCLUDED.iva_condition,
                default_point_of_sale = EXCLUDED.default_point_of_sale,
                address = EXCLUDED.address,
                start_date = EXCLUDED.start_date,
                updated_at = CURRENT_TIMESTAMP
            RETURNING *;
        `;
        const result = await db.query(query, [monday_account_id, business_name, cuit, iva_condition, default_point_of_sale, domicilio, fecha_inicio]);
        res.json(result.rows[0]);
    } catch (err) {
        console.error("Error en DB:", err);
        res.status(500).json({ error: 'Error al guardar los datos fiscales' });
    }
});

app.post('/api/certificates', upload.fields([
    { name: 'crt', maxCount: 1 },
    { name: 'key', maxCount: 1 }
]), async (req, res) => {
    const { monday_account_id } = req.body;
    const files = req.files;

    if (!files || !files['crt'] || !files['key']) {
        return res.status(400).json({ error: 'Faltan archivos' });
    }

    try {
        const companyRes = await db.query('SELECT id FROM companies WHERE monday_account_id = $1', [monday_account_id]);
        if (companyRes.rows.length === 0) return res.status(404).json({ error: 'Empresa no encontrada' });
        
        const companyId = companyRes.rows[0].id;

        // Leemos el contenido desde la MEMORIA
        const crtContent = files['crt'][0].buffer.toString('utf8');
        const keyContent = files['key'][0].buffer.toString('utf8');

        // Encriptamos la clave privada
        const encryptedKey = CryptoJS.AES.encrypt(keyContent, process.env.ENCRYPTION_KEY).toString();

        const query = `
            INSERT INTO afip_credentials (company_id, crt_file_url, encrypted_private_key, expiration_date)
            VALUES ($1, $2, $3, $4)
            ON CONFLICT (company_id) 
            DO UPDATE SET 
                crt_file_url = EXCLUDED.crt_file_url,
                encrypted_private_key = EXCLUDED.encrypted_private_key,
                expiration_date = EXCLUDED.expiration_date
            RETURNING *;
        `;
        
        const expirationDate = new Date();
        expirationDate.setFullYear(expirationDate.getFullYear() + 1);

        // Guardamos el CONTENIDO del CRT directamente en el campo que antes era para la URL
        await db.query(query, [companyId, crtContent, encryptedKey, expirationDate]);

        res.json({ message: 'Certificados guardados en DB y clave encriptada correctamente' });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Error al procesar certificados' });
    }
});

// Para desarrollo local
if (process.env.NODE_ENV !== 'production') {
    const PORT = process.env.PORT || 3001;
    app.listen(PORT, () => console.log(`Backend local en puerto ${PORT}`));
}

// Exportamos para Netlify
module.exports = app;
module.exports.handler = serverless(app);
