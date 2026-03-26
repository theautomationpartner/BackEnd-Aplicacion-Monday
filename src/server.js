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

async function getCompanyByMondayAccountId(mondayAccountId) {
    const companyQuery = `
        SELECT id, business_name, cuit, iva_condition, default_point_of_sale, address, start_date
        FROM companies
        WHERE monday_account_id = $1
        LIMIT 1;
    `;
    const companyResult = await db.query(companyQuery, [mondayAccountId]);
    return companyResult.rows[0] || null;
}

// --- RUTAS ---

app.get('/api/health', async (req, res) => {
    try {
        await db.query('SELECT NOW()');
        res.json({ status: 'ok', message: 'Servidor Serverless y DB conectados' });
    } catch (err) {
        res.status(500).json({ status: 'error', message: err.message });
    }
});

app.get('/api/setup/:mondayAccountId', async (req, res) => {
    const { mondayAccountId } = req.params;
    const { board_id, view_id, app_feature_id } = req.query;

    console.log('🔎 setup request', {
        mondayAccountId,
        board_id: board_id || null,
        view_id: view_id || null,
        app_feature_id: app_feature_id || null
    });

    try {
        const company = await getCompanyByMondayAccountId(mondayAccountId);

        if (!company) {
            return res.json({
                hasFiscalData: false,
                hasCertificates: false,
                fiscalData: null,
                certificates: null,
                visualMapping: null,
                identifiers: {
                    monday_account_id: mondayAccountId,
                    board_id: board_id || null,
                    view_id: view_id || null,
                    app_feature_id: app_feature_id || null
                }
            });
        }

        const certResult = await db.query(
            'SELECT expiration_date FROM afip_credentials WHERE company_id = $1 LIMIT 1',
            [company.id]
        );

        let visualMapping = null;
        if (board_id) {
            const mappingResult = await db.query(
                `SELECT mapping_json, is_locked, updated_at
                 FROM visual_mappings
                 WHERE company_id = $1
                   AND board_id = $2
                   AND COALESCE(view_id, '') = COALESCE($3, '')
                   AND COALESCE(app_feature_id, '') = COALESCE($4, '')
                 LIMIT 1`,
                [company.id, String(board_id), view_id || null, app_feature_id || null]
            );

            if (mappingResult.rows.length > 0) {
                visualMapping = {
                    mapping: mappingResult.rows[0].mapping_json || {},
                    is_locked: mappingResult.rows[0].is_locked,
                    updated_at: mappingResult.rows[0].updated_at || null
                };
            }
        }

        res.json({
            hasFiscalData: true,
            hasCertificates: certResult.rows.length > 0,
            fiscalData: {
                business_name: company.business_name || '',
                cuit: company.cuit || '',
                iva_condition: company.iva_condition || '',
                default_point_of_sale: company.default_point_of_sale || '',
                domicilio: company.address || '',
                fecha_inicio: company.start_date || ''
            },
            certificates: certResult.rows[0] || null,
            visualMapping,
            identifiers: {
                monday_account_id: mondayAccountId,
                board_id: board_id || null,
                view_id: view_id || null,
                app_feature_id: app_feature_id || null
            }
        });
    } catch (err) {
        console.error('❌ Error al consultar setup inicial:', err);
        res.status(500).json({ error: 'Error al consultar datos guardados' });
    }
});

app.get('/api/mappings/:mondayAccountId', async (req, res) => {
    const { mondayAccountId } = req.params;
    const { board_id, view_id, app_feature_id } = req.query;

    if (!board_id) {
        return res.status(400).json({ error: 'board_id es obligatorio' });
    }

    try {
        const company = await getCompanyByMondayAccountId(mondayAccountId);
        if (!company) {
            return res.json({ hasMapping: false, mapping: null });
        }

        const mappingResult = await db.query(
            `SELECT id, mapping_json, is_locked, created_at, updated_at
             FROM visual_mappings
             WHERE company_id = $1
               AND board_id = $2
               AND COALESCE(view_id, '') = COALESCE($3, '')
               AND COALESCE(app_feature_id, '') = COALESCE($4, '')
             LIMIT 1`,
            [company.id, String(board_id), view_id || null, app_feature_id || null]
        );

        if (mappingResult.rows.length === 0) {
            return res.json({ hasMapping: false, mapping: null });
        }

        return res.json({
            hasMapping: true,
            mapping: {
                id: mappingResult.rows[0].id,
                mapping: mappingResult.rows[0].mapping_json || {},
                is_locked: mappingResult.rows[0].is_locked,
                created_at: mappingResult.rows[0].created_at,
                updated_at: mappingResult.rows[0].updated_at
            }
        });
    } catch (err) {
        console.error('❌ Error al consultar mapeo visual:', err);
        return res.status(500).json({ error: 'Error al consultar mapeo visual' });
    }
});

app.post('/api/mappings', async (req, res) => {
    const {
        monday_account_id,
        board_id,
        view_id,
        app_feature_id,
        mapping,
        is_locked
    } = req.body;

    if (!monday_account_id || !board_id) {
        return res.status(400).json({ error: 'monday_account_id y board_id son obligatorios' });
    }

    if (!mapping || typeof mapping !== 'object' || Array.isArray(mapping)) {
        return res.status(400).json({ error: 'mapping debe ser un objeto JSON valido' });
    }

    try {
        const company = await getCompanyByMondayAccountId(String(monday_account_id));
        if (!company) {
            return res.status(404).json({ error: 'Empresa no encontrada' });
        }

        const updateResult = await db.query(
            `UPDATE visual_mappings
             SET mapping_json = $5,
                 is_locked = COALESCE($6, is_locked),
                 updated_at = CURRENT_TIMESTAMP,
                 version = version + 1
             WHERE company_id = $1
               AND board_id = $2
               AND COALESCE(view_id, '') = COALESCE($3, '')
               AND COALESCE(app_feature_id, '') = COALESCE($4, '')
             RETURNING *`,
            [
                company.id,
                String(board_id),
                view_id || null,
                app_feature_id || null,
                JSON.stringify(mapping),
                typeof is_locked === 'boolean' ? is_locked : null
            ]
        );

        if (updateResult.rows.length > 0) {
            return res.json({ message: 'Mapeo visual actualizado', mapping: updateResult.rows[0] });
        }

        const insertResult = await db.query(
            `INSERT INTO visual_mappings (
                company_id,
                board_id,
                view_id,
                app_feature_id,
                mapping_json,
                is_locked
            ) VALUES ($1, $2, $3, $4, $5, COALESCE($6, TRUE))
            RETURNING *`,
            [
                company.id,
                String(board_id),
                view_id || null,
                app_feature_id || null,
                JSON.stringify(mapping),
                typeof is_locked === 'boolean' ? is_locked : null
            ]
        );

        return res.status(201).json({ message: 'Mapeo visual creado', mapping: insertResult.rows[0] });
    } catch (err) {
        console.error('❌ Error al guardar mapeo visual:', err);
        return res.status(500).json({
            error: 'Error al guardar mapeo visual',
            details: err.message,
            code: err.code
        });
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
        console.error("❌ Error en DB:", err);
        res.status(500).json({ 
            error: 'Error al guardar los datos fiscales',
            details: err.message,
            code: err.code 
        });
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
        console.error("❌ Error al procesar certificados:", err);
        res.status(500).json({ 
            error: 'Error al procesar certificados',
            details: err.message,
            code: err.code
        });
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
