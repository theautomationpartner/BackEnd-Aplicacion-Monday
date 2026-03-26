const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');
const multer = require('multer');
const CryptoJS = require('crypto-js');
const jwt = require('jsonwebtoken');
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

function isMissingTableError(err) {
    return err?.code === '42P01';
}

function getSessionSecret() {
    return process.env.MONDAY_CLIENT_SECRET || process.env.MONDAY_SIGNING_SECRET || process.env.CLIENT_SECRET;
}

const COMPROBANTE_STATUS_FLOW = {
    trigger: 'Crear Comprobante',
    processing: 'Creando Comprobante',
    success: 'Comprobante Creado',
    error: 'Error - Mirar Comentarios',
};

function parseAuthorizationToken(req) {
    const authHeader = req.headers.authorization || req.headers.Authorization;
    if (!authHeader || typeof authHeader !== 'string') return null;
    if (authHeader.toLowerCase().startsWith('bearer ')) {
        return authHeader.slice(7).trim();
    }
    return authHeader.trim();
}

function extractMondayIdentity(decodedToken) {
    const dat = decodedToken?.dat || decodedToken?.data || {};
    const accountId = dat.account_id || decodedToken?.account_id || decodedToken?.accountId || null;
    const userId = dat.user_id || decodedToken?.user_id || decodedToken?.userId || null;
    return {
        accountId: accountId ? String(accountId) : null,
        userId: userId ? String(userId) : null,
    };
}

function requireMondaySession(req, res, next) {
    const secret = getSessionSecret();
    if (!secret) {
        return res.status(500).json({ error: 'Falta configurar MONDAY_CLIENT_SECRET en el backend' });
    }

    const token = parseAuthorizationToken(req);
    if (!token) {
        return res.status(401).json({ error: 'Falta Authorization Bearer sessionToken de monday' });
    }

    try {
        const decoded = jwt.verify(token, secret);
        const identity = extractMondayIdentity(decoded);
        if (!identity.accountId) {
            return res.status(401).json({ error: 'sessionToken inválido: account_id ausente' });
        }

        req.mondayIdentity = identity;
        return next();
    } catch (err) {
        return res.status(401).json({ error: 'sessionToken inválido o vencido' });
    }
}

function ensureAccountMatch(req, res, providedAccountId) {
    if (!req.mondayIdentity?.accountId || !providedAccountId) {
        res.status(401).json({ error: 'No se pudo validar la cuenta monday desde sessionToken' });
        return false;
    }

    if (String(req.mondayIdentity.accountId) !== String(providedAccountId)) {
        res.status(403).json({ error: 'Cuenta monday no autorizada para esta operación' });
        return false;
    }

    return true;
}

function isValidHttpsUrl(value) {
    if (!value || typeof value !== 'string') return false;
    try {
        const parsed = new URL(value);
        return parsed.protocol === 'https:';
    } catch (err) {
        return false;
    }
}

async function mondayApiRequest(query, variables = {}) {
    const mondayApiToken = (process.env.MONDAY_API_TOKEN || '').trim();
    if (!mondayApiToken) {
        throw new Error('Falta MONDAY_API_TOKEN para consultar datos en monday');
    }

    const response = await fetch('https://api.monday.com/v2', {
        method: 'POST',
        headers: {
            Authorization: mondayApiToken,
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({ query, variables }),
    });

    const data = await response.json();
    if (!response.ok || data?.errors?.length) {
        const details = data?.errors?.map((err) => err.message).join(' | ') || response.statusText;
        throw new Error(`Error monday API: ${details}`);
    }

    return data?.data;
}

function toNumberOrNull(value) {
    if (value === null || value === undefined || value === '') return null;
    const normalized = String(value).trim().replace(',', '.');
    const parsed = Number(normalized);
    return Number.isFinite(parsed) ? parsed : null;
}

function getColumnTextById(columnValues, columnId) {
    if (!columnId) return '';
    const found = (columnValues || []).find((column) => column.id === columnId);
    return found?.text || '';
}

function sumLineTotals(lines) {
    return lines.reduce((acc, line) => {
        const quantity = toNumberOrNull(line.quantity) || 0;
        const unitPrice = toNumberOrNull(line.unit_price) || 0;
        return acc + (quantity * unitPrice);
    }, 0);
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

app.get('/api/setup/:mondayAccountId', requireMondaySession, async (req, res) => {
    const { mondayAccountId } = req.params;
    const { board_id, view_id, app_feature_id } = req.query;

    if (!ensureAccountMatch(req, res, mondayAccountId)) return;

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
                boardConfig: null,
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

        let boardConfig = null;
        if (board_id) {
            try {
                const boardConfigResult = await db.query(
                    `SELECT status_column_id, trigger_label, success_label, error_label, required_columns_json, updated_at
                     FROM board_automation_configs
                     WHERE company_id = $1
                       AND board_id = $2
                       AND COALESCE(view_id, '') = COALESCE($3, '')
                       AND COALESCE(app_feature_id, '') = COALESCE($4, '')
                     LIMIT 1`,
                    [company.id, String(board_id), view_id || null, app_feature_id || null]
                );

                if (boardConfigResult.rows.length > 0) {
                    const row = boardConfigResult.rows[0];
                    boardConfig = {
                        status_column_id: row.status_column_id || '',
                        trigger_label: row.trigger_label || COMPROBANTE_STATUS_FLOW.trigger,
                        processing_label: COMPROBANTE_STATUS_FLOW.processing,
                        success_label: row.success_label || COMPROBANTE_STATUS_FLOW.success,
                        error_label: row.error_label || COMPROBANTE_STATUS_FLOW.error,
                        required_columns: row.required_columns_json || [],
                        updated_at: row.updated_at || null
                    };
                }
            } catch (boardConfigErr) {
                if (!isMissingTableError(boardConfigErr)) {
                    throw boardConfigErr;
                }
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
            boardConfig,
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

app.get('/api/board-config/:mondayAccountId', requireMondaySession, async (req, res) => {
    const { mondayAccountId } = req.params;
    const { board_id, view_id, app_feature_id } = req.query;

    if (!ensureAccountMatch(req, res, mondayAccountId)) return;

    if (!board_id) {
        return res.status(400).json({ error: 'board_id es obligatorio' });
    }

    try {
        const company = await getCompanyByMondayAccountId(mondayAccountId);
        if (!company) {
            return res.json({ hasConfig: false, config: null });
        }

        const result = await db.query(
            `SELECT id, status_column_id, trigger_label, success_label, error_label, required_columns_json, updated_at
             FROM board_automation_configs
             WHERE company_id = $1
               AND board_id = $2
               AND COALESCE(view_id, '') = COALESCE($3, '')
               AND COALESCE(app_feature_id, '') = COALESCE($4, '')
             LIMIT 1`,
            [company.id, String(board_id), view_id || null, app_feature_id || null]
        );

        if (result.rows.length === 0) {
            return res.json({ hasConfig: false, config: null });
        }

        const row = result.rows[0];
        return res.json({
            hasConfig: true,
            config: {
                id: row.id,
                status_column_id: row.status_column_id || '',
                trigger_label: row.trigger_label || COMPROBANTE_STATUS_FLOW.trigger,
                processing_label: COMPROBANTE_STATUS_FLOW.processing,
                success_label: row.success_label || COMPROBANTE_STATUS_FLOW.success,
                error_label: row.error_label || COMPROBANTE_STATUS_FLOW.error,
                required_columns: row.required_columns_json || [],
                updated_at: row.updated_at || null
            }
        });
    } catch (err) {
        if (isMissingTableError(err)) {
            return res.status(503).json({
                error: 'Falta crear la tabla board_automation_configs en la base de datos'
            });
        }

        console.error('❌ Error al consultar configuración de tablero:', err);
        return res.status(500).json({ error: 'Error al consultar configuración de tablero' });
    }
});

app.post('/api/board-config', requireMondaySession, async (req, res) => {
    const {
        monday_account_id,
        board_id,
        view_id,
        app_feature_id,
        status_column_id,
        required_columns
    } = req.body;

    const accountId = String(monday_account_id || req.mondayIdentity.accountId || '');

    if (!accountId || !board_id || !status_column_id) {
        return res.status(400).json({ error: 'monday_account_id, board_id y status_column_id son obligatorios' });
    }

    if (!ensureAccountMatch(req, res, accountId)) return;

    if (!Array.isArray(required_columns)) {
        return res.status(400).json({ error: 'required_columns debe ser un array' });
    }

    try {
        const company = await getCompanyByMondayAccountId(accountId);
        if (!company) {
            return res.status(404).json({ error: 'Empresa no encontrada' });
        }

        const updateResult = await db.query(
            `UPDATE board_automation_configs
             SET status_column_id = $5,
                 trigger_label = $6,
                 success_label = $7,
                 error_label = $8,
                 required_columns_json = $9,
                 updated_at = CURRENT_TIMESTAMP
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
                String(status_column_id),
                COMPROBANTE_STATUS_FLOW.trigger,
                COMPROBANTE_STATUS_FLOW.success,
                COMPROBANTE_STATUS_FLOW.error,
                JSON.stringify(required_columns)
            ]
        );

        if (updateResult.rows.length > 0) {
            return res.json({ message: 'Configuración de tablero actualizada', config: updateResult.rows[0] });
        }

        const insertResult = await db.query(
            `INSERT INTO board_automation_configs (
                company_id,
                board_id,
                view_id,
                app_feature_id,
                status_column_id,
                trigger_label,
                success_label,
                error_label,
                required_columns_json
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
            RETURNING *`,
            [
                company.id,
                String(board_id),
                view_id || null,
                app_feature_id || null,
                String(status_column_id),
                COMPROBANTE_STATUS_FLOW.trigger,
                COMPROBANTE_STATUS_FLOW.success,
                COMPROBANTE_STATUS_FLOW.error,
                JSON.stringify(required_columns)
            ]
        );

        return res.status(201).json({ message: 'Configuración de tablero creada', config: insertResult.rows[0] });
    } catch (err) {
        if (isMissingTableError(err)) {
            return res.status(503).json({
                error: 'Falta crear la tabla board_automation_configs en la base de datos'
            });
        }

        console.error('❌ Error al guardar configuración de tablero:', err);
        return res.status(500).json({
            error: 'Error al guardar configuración de tablero',
            details: err.message,
            code: err.code
        });
    }
});

app.get('/api/mappings/:mondayAccountId', requireMondaySession, async (req, res) => {
    const { mondayAccountId } = req.params;
    const { board_id, view_id, app_feature_id } = req.query;

    if (!ensureAccountMatch(req, res, mondayAccountId)) return;

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

app.post('/api/mappings', requireMondaySession, async (req, res) => {
    const {
        monday_account_id,
        board_id,
        view_id,
        app_feature_id,
        mapping,
        is_locked
    } = req.body;

    const accountId = String(monday_account_id || req.mondayIdentity.accountId || '');

    if (!accountId || !board_id) {
        return res.status(400).json({ error: 'monday_account_id y board_id son obligatorios' });
    }

    if (!ensureAccountMatch(req, res, accountId)) return;

    if (!mapping || typeof mapping !== 'object' || Array.isArray(mapping)) {
        return res.status(400).json({ error: 'mapping debe ser un objeto JSON valido' });
    }

    try {
        const company = await getCompanyByMondayAccountId(accountId);
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

app.post('/api/companies', requireMondaySession, async (req, res) => {
    const { monday_account_id, business_name, cuit, iva_condition, default_point_of_sale, domicilio, fecha_inicio } = req.body;
    const accountId = String(monday_account_id || req.mondayIdentity.accountId || '');

    if (!accountId) {
        return res.status(400).json({ error: 'monday_account_id es obligatorio' });
    }

    if (!ensureAccountMatch(req, res, accountId)) return;

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
        const result = await db.query(query, [accountId, business_name, cuit, iva_condition, default_point_of_sale, domicilio, fecha_inicio]);
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

app.post('/api/certificates', requireMondaySession, upload.fields([
    { name: 'crt', maxCount: 1 },
    { name: 'key', maxCount: 1 }
]), async (req, res) => {
    const { monday_account_id } = req.body;
    const accountId = String(monday_account_id || req.mondayIdentity.accountId || '');

    if (!accountId) {
        return res.status(400).json({ error: 'monday_account_id es obligatorio' });
    }

    if (!ensureAccountMatch(req, res, accountId)) return;

    const files = req.files;

    if (!files || !files['crt'] || !files['key']) {
        return res.status(400).json({ error: 'Faltan archivos' });
    }

    try {
        const companyRes = await db.query('SELECT id FROM companies WHERE monday_account_id = $1', [accountId]);
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

app.post('/api/invoices/emit-c', requireMondaySession, async (req, res) => {
    const {
        monday_account_id,
        board_id,
        item_id
    } = req.body;

    const accountId = String(monday_account_id || req.mondayIdentity.accountId || '');
    const boardId = String(board_id || '').trim();
    const itemId = String(item_id || '').trim();

    if (!accountId || !boardId || !itemId) {
        return res.status(400).json({ error: 'monday_account_id, board_id e item_id son obligatorios' });
    }

    if (!ensureAccountMatch(req, res, accountId)) return;

    try {
        const company = await getCompanyByMondayAccountId(accountId);
        if (!company) {
            return res.status(404).json({ error: 'Empresa no encontrada para la cuenta monday' });
        }

        const certResult = await db.query(
            'SELECT id FROM afip_credentials WHERE company_id = $1 LIMIT 1',
            [company.id]
        );
        if (certResult.rows.length === 0) {
            return res.status(400).json({ error: 'Faltan certificados AFIP para emitir comprobante' });
        }

        const mappingResult = await db.query(
            `SELECT mapping_json
             FROM visual_mappings
             WHERE company_id = $1
               AND board_id = $2
             ORDER BY updated_at DESC
             LIMIT 1`,
            [company.id, boardId]
        );

        if (mappingResult.rows.length === 0 || !mappingResult.rows[0].mapping_json) {
            return res.status(400).json({ error: 'Falta mapeo visual guardado para este tablero' });
        }

        const mapping = mappingResult.rows[0].mapping_json;

        const mondayData = await mondayApiRequest(
            `query GetItemForInvoice($boardId: [ID!], $itemId: [ID!]) {
                boards(ids: $boardId) {
                    items_page(limit: 1, query_params: { ids: $itemId }) {
                        items {
                            id
                            name
                            column_values {
                                id
                                text
                                value
                            }
                            subitems {
                                id
                                name
                                column_values {
                                    id
                                    text
                                    value
                                }
                            }
                        }
                    }
                }
            }`,
            {
                boardId: [Number(boardId)],
                itemId: [Number(itemId)],
            }
        );

        const item = mondayData?.boards?.[0]?.items_page?.items?.[0];
        if (!item) {
            return res.status(404).json({ error: 'No se encontró el item en monday' });
        }

        const mainColumns = item.column_values || [];
        const subitems = item.subitems || [];

        const fechaEmisionRaw = getColumnTextById(mainColumns, mapping.fecha_emision);
        const receptorCuit = getColumnTextById(mainColumns, mapping.receptor_cuit) || null;

        const rawLines = subitems.map((subitem) => ({
            subitem_id: Number(subitem.id),
            concept: getColumnTextById(subitem.column_values, mapping.concepto) || subitem.name || '',
            quantity: getColumnTextById(subitem.column_values, mapping.cantidad),
            unit_price: getColumnTextById(subitem.column_values, mapping.precio_unitario),
        }));

        const validLines = rawLines.filter((line) => (
            line.concept &&
            toNumberOrNull(line.quantity) !== null &&
            toNumberOrNull(line.unit_price) !== null
        ));

        if (validLines.length === 0) {
            return res.status(400).json({ error: 'No hay subitems válidos para emitir Factura C' });
        }

        const totalAmount = sumLineTotals(validLines);

        const facturaCDraft = {
            tipo_comprobante: 'C',
            cuit_emisor: company.cuit,
            punto_venta: company.default_point_of_sale,
            fecha_emision: fechaEmisionRaw || new Date().toISOString().slice(0, 10),
            receptor_cuit_o_dni: receptorCuit,
            importe_total: Number(totalAmount.toFixed(2)),
            lineas: validLines.map((line) => {
                const quantity = toNumberOrNull(line.quantity) || 0;
                const unitPrice = toNumberOrNull(line.unit_price) || 0;
                return {
                    descripcion: line.concept,
                    cantidad: Number(quantity.toFixed(2)),
                    precio_unitario: Number(unitPrice.toFixed(2)),
                    subtotal: Number((quantity * unitPrice).toFixed(2)),
                };
            }),
        };

        return res.status(202).json({
            message: 'Factura C preparada en backend (siguiente paso: autorización AFIP WSFE)',
            item_id: Number(itemId),
            board_id: Number(boardId),
            draft: facturaCDraft,
            status_flow: COMPROBANTE_STATUS_FLOW,
        });
    } catch (err) {
        console.error('❌ Error al preparar Factura C en backend:', err);
        return res.status(500).json({
            error: 'Error al preparar Factura C',
            details: err.message,
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
