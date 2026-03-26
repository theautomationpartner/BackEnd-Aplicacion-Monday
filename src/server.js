const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');
const multer = require('multer');
const CryptoJS = require('crypto-js');
const jwt = require('jsonwebtoken');
const forge = require('node-forge');
const PDFDocument = require('pdfkit');
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
        SELECT id, monday_account_id, business_name, cuit, iva_condition, default_point_of_sale, address, start_date
        FROM companies
        WHERE monday_account_id::text = $1
        LIMIT 1;
    `;
    const companyResult = await db.query(companyQuery, [String(mondayAccountId)]);
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
    return {
        accountId: accountId ? String(accountId) : null,
        userId: null,
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

function createDebugId(prefix = 'dbg') {
    const random = Math.random().toString(36).slice(2, 8);
    return `${prefix}_${Date.now()}_${random}`;
}

async function getUserTokenSchemaDiagnostics() {
    const diagnostics = {
        database: null,
        db_user: null,
        companies_monday_account_id_type: null,
        user_api_tokens_monday_user_id_type: null,
        user_api_tokens_v2_encrypted_api_token_type: null,
        user_api_tokens_v3_monday_account_id_type: null,
    };

    try {
        const dbInfoResult = await db.query('SELECT current_database() AS database, current_user AS db_user');
        if (dbInfoResult.rows[0]) {
            diagnostics.database = dbInfoResult.rows[0].database || null;
            diagnostics.db_user = dbInfoResult.rows[0].db_user || null;
        }

        const columnTypesResult = await db.query(
            `SELECT table_name, column_name, data_type
             FROM information_schema.columns
                         WHERE table_name IN ('companies', 'user_api_tokens', 'user_api_tokens_v2', 'user_api_tokens_v3')
                             AND column_name IN ('monday_account_id', 'monday_user_id', 'encrypted_api_token')`
        );

        for (const row of columnTypesResult.rows) {
            if (row.table_name === 'companies' && row.column_name === 'monday_account_id') {
                diagnostics.companies_monday_account_id_type = row.data_type;
            }
            if (row.table_name === 'user_api_tokens' && row.column_name === 'monday_user_id') {
                diagnostics.user_api_tokens_monday_user_id_type = row.data_type;
            }
            if (row.table_name === 'user_api_tokens_v2' && row.column_name === 'encrypted_api_token') {
                diagnostics.user_api_tokens_v2_encrypted_api_token_type = row.data_type;
            }
            if (row.table_name === 'user_api_tokens_v3' && row.column_name === 'monday_account_id') {
                diagnostics.user_api_tokens_v3_monday_account_id_type = row.data_type;
            }
        }
    } catch (diagErr) {
        diagnostics.diagnostics_error = diagErr.message;
    }

    return diagnostics;
}

function normalizePem(rawValue, label) {
    if (!rawValue) return '';
    const trimmed = String(rawValue).trim();
    if (trimmed.includes(`-----BEGIN ${label}-----`)) {
        return trimmed;
    }

    const body = trimmed
        .replace(/-----BEGIN[^-]+-----/g, '')
        .replace(/-----END[^-]+-----/g, '')
        .replace(/\s+/g, '');
    const chunks = body.match(/.{1,64}/g) || [];
    return `-----BEGIN ${label}-----\n${chunks.join('\n')}\n-----END ${label}-----`;
}

function getAfipEnvironment() {
    const env = (process.env.AFIP_ENV || 'homologation').toLowerCase();
    return env === 'production' ? 'production' : 'homologation';
}

function getAfipEndpoints() {
    const env = getAfipEnvironment();
    if (env === 'production') {
        return {
            wsaa: 'https://wsaa.afip.gov.ar/ws/services/LoginCms',
            wsfe: 'https://servicios1.afip.gov.ar/wsfev1/service.asmx',
        };
    }

    return {
        wsaa: 'https://wsaahomo.afip.gov.ar/ws/services/LoginCms',
        wsfe: 'https://wswhomo.afip.gov.ar/wsfev1/service.asmx',
    };
}

function buildLoginTicketRequest(serviceName) {
    const now = new Date();
    const generationTime = new Date(now.getTime() - 60 * 1000).toISOString();
    const expirationTime = new Date(now.getTime() + 10 * 60 * 1000).toISOString();
    const uniqueId = Math.floor(now.getTime() / 1000);

    return `<?xml version="1.0" encoding="UTF-8"?>\n<loginTicketRequest version="1.0">\n  <header>\n    <uniqueId>${uniqueId}</uniqueId>\n    <generationTime>${generationTime}</generationTime>\n    <expirationTime>${expirationTime}</expirationTime>\n  </header>\n  <service>${serviceName}</service>\n</loginTicketRequest>`;
}

function signTraCmsBase64(traXml, certPem, keyPem) {
    const certificate = forge.pki.certificateFromPem(certPem);
    const privateKey = forge.pki.privateKeyFromPem(keyPem);

    const p7 = forge.pkcs7.createSignedData();
    p7.content = forge.util.createBuffer(traXml, 'utf8');
    p7.addCertificate(certificate);
    p7.addSigner({
        key: privateKey,
        certificate,
        digestAlgorithm: forge.pki.oids.sha256,
        authenticatedAttributes: [
            {
                type: forge.pki.oids.contentType,
                value: forge.pki.oids.data,
            },
            {
                type: forge.pki.oids.messageDigest,
            },
            {
                type: forge.pki.oids.signingTime,
                value: new Date(),
            },
        ],
    });
    p7.sign({ detached: true });

    const der = forge.asn1.toDer(p7.toAsn1()).getBytes();
    return forge.util.encode64(der);
}

function xmlEscape(value) {
    return String(value)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&apos;');
}

function extractXmlTag(xml, tagName) {
    const regex = new RegExp(`<${tagName}>([\\s\\S]*?)<\\/${tagName}>`, 'i');
    const match = String(xml || '').match(regex);
    return match?.[1]?.trim() || '';
}

async function afipLoginCms(certPem, keyPem) {
    const endpoints = getAfipEndpoints();
    const tra = buildLoginTicketRequest('wsfe');
    const cms = signTraCmsBase64(tra, certPem, keyPem);

    const soapBody = `<?xml version="1.0" encoding="UTF-8"?>\n<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:ar="http://wsaa.view.sua.dvadac.desein.afip.gov">\n  <soapenv:Header/>\n  <soapenv:Body>\n    <ar:loginCms>\n      <ar:in0>${cms}</ar:in0>\n    </ar:loginCms>\n  </soapenv:Body>\n</soapenv:Envelope>`;

    const response = await fetch(endpoints.wsaa, {
        method: 'POST',
        headers: {
            'Content-Type': 'text/xml; charset=utf-8',
            SOAPAction: '',
        },
        body: soapBody,
    });

    const xml = await response.text();
    if (!response.ok) {
        throw new Error(`WSAA HTTP ${response.status}: ${xml.slice(0, 500)}`);
    }

    const loginCmsReturn = extractXmlTag(xml, 'loginCmsReturn');
    const token = extractXmlTag(loginCmsReturn, 'token');
    const sign = extractXmlTag(loginCmsReturn, 'sign');

    if (!token || !sign) {
        throw new Error(`WSAA sin token/sign válido: ${xml.slice(0, 500)}`);
    }

    return { token, sign };
}

async function afipGetLastVoucher({ token, sign, cuit, pointOfSale, cbteType }) {
    const endpoints = getAfipEndpoints();
    const soapBody = `<?xml version="1.0" encoding="UTF-8"?>\n<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:ar="http://ar.gov.afip.dif.FEV1/">\n  <soapenv:Header/>\n  <soapenv:Body>\n    <ar:FECompUltimoAutorizado>\n      <ar:Auth>\n        <ar:Token>${xmlEscape(token)}</ar:Token>\n        <ar:Sign>${xmlEscape(sign)}</ar:Sign>\n        <ar:Cuit>${xmlEscape(cuit)}</ar:Cuit>\n      </ar:Auth>\n      <ar:PtoVta>${xmlEscape(pointOfSale)}</ar:PtoVta>\n      <ar:CbteTipo>${xmlEscape(cbteType)}</ar:CbteTipo>\n    </ar:FECompUltimoAutorizado>\n  </soapenv:Body>\n</soapenv:Envelope>`;

    const response = await fetch(endpoints.wsfe, {
        method: 'POST',
        headers: {
            'Content-Type': 'text/xml; charset=utf-8',
            SOAPAction: 'http://ar.gov.afip.dif.FEV1/FECompUltimoAutorizado',
        },
        body: soapBody,
    });

    const xml = await response.text();
    if (!response.ok) {
        throw new Error(`FECompUltimoAutorizado HTTP ${response.status}: ${xml.slice(0, 500)}`);
    }

    const cbteNro = extractXmlTag(xml, 'CbteNro');
    const parsed = Number(cbteNro);
    if (!Number.isFinite(parsed)) {
        throw new Error(`No se pudo obtener último comprobante: ${xml.slice(0, 500)}`);
    }
    return parsed;
}

async function afipIssueFacturaC({ token, sign, cuit, pointOfSale, draft }) {
    const endpoints = getAfipEndpoints();
    const cbteType = 11;
    const lastVoucher = await afipGetLastVoucher({ token, sign, cuit, pointOfSale, cbteType });
    const nextVoucher = lastVoucher + 1;

    const docNumberDigits = String(draft.receptor_cuit_o_dni || '').replace(/\D/g, '');
    const docType = docNumberDigits.length === 11 ? 80 : (docNumberDigits.length >= 7 ? 96 : 99);
    const docNumber = docNumberDigits ? Number(docNumberDigits) : 0;

    const dateYYYYMMDD = String(draft.fecha_emision || '').replace(/-/g, '') || new Date().toISOString().slice(0, 10).replace(/-/g, '');
    const total = Number(draft.importe_total || 0).toFixed(2);

    const soapBody = `<?xml version="1.0" encoding="UTF-8"?>\n<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:ar="http://ar.gov.afip.dif.FEV1/">\n  <soapenv:Header/>\n  <soapenv:Body>\n    <ar:FECAESolicitar>\n      <ar:Auth>\n        <ar:Token>${xmlEscape(token)}</ar:Token>\n        <ar:Sign>${xmlEscape(sign)}</ar:Sign>\n        <ar:Cuit>${xmlEscape(cuit)}</ar:Cuit>\n      </ar:Auth>\n      <ar:FeCAEReq>\n        <ar:FeCabReq>\n          <ar:CantReg>1</ar:CantReg>\n          <ar:PtoVta>${xmlEscape(pointOfSale)}</ar:PtoVta>\n          <ar:CbteTipo>${cbteType}</ar:CbteTipo>\n        </ar:FeCabReq>\n        <ar:FeDetReq>\n          <ar:FECAEDetRequest>\n            <ar:Concepto>1</ar:Concepto>\n            <ar:DocTipo>${docType}</ar:DocTipo>\n            <ar:DocNro>${docNumber}</ar:DocNro>\n            <ar:CbteDesde>${nextVoucher}</ar:CbteDesde>\n            <ar:CbteHasta>${nextVoucher}</ar:CbteHasta>\n            <ar:CbteFch>${dateYYYYMMDD}</ar:CbteFch>\n            <ar:ImpTotal>${total}</ar:ImpTotal>\n            <ar:ImpTotConc>0.00</ar:ImpTotConc>\n            <ar:ImpNeto>${total}</ar:ImpNeto>\n            <ar:ImpOpEx>0.00</ar:ImpOpEx>\n            <ar:ImpTrib>0.00</ar:ImpTrib>\n            <ar:ImpIVA>0.00</ar:ImpIVA>\n            <ar:MonId>PES</ar:MonId>\n            <ar:MonCotiz>1.000</ar:MonCotiz>\n          </ar:FECAEDetRequest>\n        </ar:FeDetReq>\n      </ar:FeCAEReq>\n    </ar:FECAESolicitar>\n  </soapenv:Body>\n</soapenv:Envelope>`;

    const response = await fetch(endpoints.wsfe, {
        method: 'POST',
        headers: {
            'Content-Type': 'text/xml; charset=utf-8',
            SOAPAction: 'http://ar.gov.afip.dif.FEV1/FECAESolicitar',
        },
        body: soapBody,
    });

    const xml = await response.text();
    if (!response.ok) {
        throw new Error(`FECAESolicitar HTTP ${response.status}: ${xml.slice(0, 500)}`);
    }

    const result = extractXmlTag(xml, 'Resultado');
    const cae = extractXmlTag(xml, 'CAE');
    const caeExpiration = extractXmlTag(xml, 'CAEFchVto');
    const observation = extractXmlTag(xml, 'Msg') || extractXmlTag(xml, 'Obs') || '';

    return {
        resultado: result || 'N/D',
        cae: cae || null,
        cae_vencimiento: caeExpiration || null,
        numero_comprobante: nextVoucher,
        observacion: observation || null,
        raw_xml: xml.slice(0, 2000),
    };
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

async function ensureInvoiceEmissionsTable() {
    await db.query(
        `CREATE TABLE IF NOT EXISTS invoice_emissions (
            id SERIAL PRIMARY KEY,
            company_id INTEGER NOT NULL,
            board_id TEXT NOT NULL,
            item_id TEXT NOT NULL,
            invoice_type TEXT NOT NULL,
            status TEXT NOT NULL,
            request_json JSONB,
            draft_json JSONB,
            afip_result_json JSONB,
            pdf_base64 TEXT,
            error_message TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            UNIQUE (company_id, board_id, item_id, invoice_type)
        )`
    );
}

async function ensureUserApiTokensTable() {
    await db.query(
        `CREATE TABLE IF NOT EXISTS user_api_tokens (
            id SERIAL PRIMARY KEY,
            company_id INTEGER NOT NULL,
            monday_user_id TEXT NOT NULL,
            encrypted_api_token TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            UNIQUE (company_id, monday_user_id)
        )`
    );

    // Compatibility migration: some environments may have monday_user_id as INTEGER.
    // Monday user IDs can be UUID strings, so the column must be TEXT.
    await db.query(
        `ALTER TABLE user_api_tokens
         ALTER COLUMN monday_user_id TYPE TEXT
         USING monday_user_id::text`
    );
}

async function ensureUserApiTokensV2Table() {
    await db.query(
        `CREATE TABLE IF NOT EXISTS user_api_tokens_v2 (
            id SERIAL PRIMARY KEY,
            company_id INTEGER NOT NULL UNIQUE,
            encrypted_api_token TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )`
    );
}

async function ensureUserApiTokensV3Table() {
    await db.query(
        `CREATE TABLE IF NOT EXISTS user_api_tokens_v3 (
            id SERIAL PRIMARY KEY,
            monday_account_id TEXT NOT NULL UNIQUE,
            encrypted_api_token TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )`
    );
}

async function getStoredMondayUserApiToken({ mondayAccountId }) {
    if (!mondayAccountId) return null;

    await ensureUserApiTokensV3Table();

    const result = await db.query(
        `SELECT encrypted_api_token
         FROM user_api_tokens_v3
         WHERE monday_account_id = $1
         LIMIT 1`,
        [String(mondayAccountId)]
    );

    if (result.rows.length === 0) return null;

    const decrypted = CryptoJS.AES.decrypt(
        result.rows[0].encrypted_api_token,
        process.env.ENCRYPTION_KEY
    ).toString(CryptoJS.enc.Utf8);

    return decrypted || null;
}

async function getInvoicePdfColumnId({ companyId, boardId }) {
    if (!companyId || !boardId) return null;

    const configResult = await db.query(
        `SELECT required_columns_json
         FROM board_automation_configs
         WHERE company_id = $1
           AND board_id = $2
         ORDER BY updated_at DESC
         LIMIT 1`,
        [companyId, String(boardId)]
    );

    const requiredColumns = configResult.rows[0]?.required_columns_json;
    if (!Array.isArray(requiredColumns)) return null;

    const invoicePdfColumn = requiredColumns.find((column) => column?.key === 'invoice_pdf');
    const resolvedColumnId = invoicePdfColumn?.resolved_column_id;

    return resolvedColumnId ? String(resolvedColumnId) : null;
}

async function uploadPdfToMondayFileColumn({ apiToken, itemId, fileColumnId, pdfBuffer, filename }) {
    if (!apiToken || !itemId || !fileColumnId || !pdfBuffer) {
        return { uploaded: false, reason: 'missing_upload_inputs' };
    }

    const operations = {
        query: `mutation ($itemId: ID!, $columnId: String!, $file: File!) {
          add_file_to_column(item_id: $itemId, column_id: $columnId, file: $file) { id }
        }`,
        variables: {
            itemId: Number(itemId),
            columnId: String(fileColumnId),
            file: null,
        },
    };

    const map = { 0: ['variables.file'] };
    const formData = new FormData();
    formData.append('operations', JSON.stringify(operations));
    formData.append('map', JSON.stringify(map));
    formData.append('0', new Blob([pdfBuffer], { type: 'application/pdf' }), filename || 'comprobante.pdf');

    const response = await fetch('https://api.monday.com/v2/file', {
        method: 'POST',
        headers: {
            Authorization: String(apiToken).trim(),
        },
        body: formData,
    });

    const contentType = response.headers.get('content-type') || '';
    let payload = null;
    if (contentType.includes('application/json')) {
        payload = await response.json();
    } else {
        payload = { raw: await response.text() };
    }

    if (!response.ok) {
        const details = typeof payload === 'string' ? payload : JSON.stringify(payload || {});
        throw new Error(`Monday file upload HTTP ${response.status}: ${details.slice(0, 400)}`);
    }

    if (payload?.errors?.length) {
        throw new Error(`Monday file upload error: ${JSON.stringify(payload.errors).slice(0, 400)}`);
    }

    const uploadedAssetId = payload?.data?.add_file_to_column?.id || null;
    return {
        uploaded: Boolean(uploadedAssetId),
        asset_id: uploadedAssetId,
    };
}

function generateFacturaCPdfBuffer({ company, draft, afipResult, itemId }) {
    return new Promise((resolve, reject) => {
        try {
            const doc = new PDFDocument({ size: 'A4', margin: 40 });
            const buffers = [];
            doc.on('data', (chunk) => buffers.push(chunk));
            doc.on('end', () => resolve(Buffer.concat(buffers)));
            doc.on('error', reject);

            doc.fontSize(18).text('Factura C', { align: 'center' });
            doc.moveDown(0.5);
            doc.fontSize(11).text(`Emisor: ${company.business_name || 'N/D'}`);
            doc.text(`CUIT emisor: ${draft.cuit_emisor || 'N/D'}`);
            doc.text(`Punto de venta: ${draft.punto_venta || 'N/D'}`);
            doc.text(`Fecha emisión: ${draft.fecha_emision || 'N/D'}`);
            doc.text(`Item Monday: ${itemId}`);
            doc.moveDown(0.5);

            if (afipResult?.cae) {
                doc.text(`CAE: ${afipResult.cae}`);
                doc.text(`Vto CAE: ${afipResult.cae_vencimiento || 'N/D'}`);
                doc.text(`Comprobante nro: ${afipResult.numero_comprobante || 'N/D'}`);
                doc.text(`Resultado AFIP: ${afipResult.resultado || 'N/D'}`);
            }

            doc.moveDown();
            doc.fontSize(12).text('Detalle', { underline: true });
            doc.moveDown(0.3);
            doc.fontSize(10);

            (draft.lineas || []).forEach((line, index) => {
                doc.text(`${index + 1}. ${line.descripcion || 'Sin descripción'}`);
                doc.text(`   Cantidad: ${line.cantidad} | Precio unitario: ${line.precio_unitario} | Subtotal: ${line.subtotal}`);
            });

            doc.moveDown();
            doc.fontSize(12).text(`Importe total: ${draft.importe_total || 0}`);
            doc.end();
        } catch (err) {
            reject(err);
        }
    });
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

const getUserApiTokenHandler = async (req, res) => {
    const { mondayAccountId } = req.params;
    if (!ensureAccountMatch(req, res, mondayAccountId)) return;

    try {
        const company = await getCompanyByMondayAccountId(mondayAccountId);
        if (!company) {
            return res.json({ has_token: false });
        }

        await ensureUserApiTokensV3Table();
        const tokenResult = await db.query(
            `SELECT id
             FROM user_api_tokens_v3
             WHERE monday_account_id = $1
             LIMIT 1`,
            [String(accountId)]
        );

        return res.json({ has_token: tokenResult.rows.length > 0 });
    } catch (err) {
        console.error('❌ Error al consultar token de usuario monday:', err);
        return res.status(500).json({ error: 'Error al consultar token de usuario' });
    }
};

app.get('/api/user-api-token/:mondayAccountId', requireMondaySession, getUserApiTokenHandler);
app.get('/api/user-api-token-v2/:mondayAccountId', requireMondaySession, getUserApiTokenHandler);

const saveUserApiTokenHandler = async (req, res) => {
    const { monday_account_id, api_token } = req.body;
    const accountId = String(monday_account_id || req.mondayIdentity.accountId || '');
    const debugId = createDebugId('save_token');

    if (!accountId) {
        return res.status(400).json({ error: 'monday_account_id es obligatorio' });
    }

    if (!ensureAccountMatch(req, res, accountId)) return;

    if (!api_token || !String(api_token).trim()) {
        return res.status(400).json({ error: 'api_token es obligatorio' });
    }

    if (!process.env.ENCRYPTION_KEY) {
        return res.status(500).json({ error: 'Falta ENCRYPTION_KEY en backend' });
    }

    try {
        console.log('ℹ️ saveUserApiToken start', {
            debug_id: debugId,
            account_id: accountId,
            token_length: String(api_token || '').length,
            identity_account_id: req.mondayIdentity?.accountId || null,
        });

        const company = await getCompanyByMondayAccountId(accountId);
        if (!company) {
            return res.status(404).json({ error: 'Empresa no encontrada' });
        }

        await ensureUserApiTokensV3Table();
        const encryptedToken = CryptoJS.AES.encrypt(String(api_token).trim(), process.env.ENCRYPTION_KEY).toString();

        await db.query(
            `INSERT INTO user_api_tokens_v3 (monday_account_id, encrypted_api_token)
             VALUES ($1, $2)
             ON CONFLICT (monday_account_id)
             DO UPDATE SET
               encrypted_api_token = EXCLUDED.encrypted_api_token,
               updated_at = CURRENT_TIMESTAMP`,
            [String(accountId), encryptedToken]
        );

        console.log('✅ saveUserApiToken success', {
            debug_id: debugId,
            company_id: company.id,
            storage: 'user_api_tokens_v3',
        });

        return res.json({
            message: 'Token de usuario guardado correctamente',
            debug_id: debugId,
        });
    } catch (err) {
        const diagnostics = await getUserTokenSchemaDiagnostics();
        console.error('❌ Error al guardar token de usuario monday:', {
            debug_id: debugId,
            error_message: err.message,
            error_code: err.code,
            error_detail: err.detail,
            error_where: err.where,
            diagnostics,
        });
        return res.status(500).json({
            error: 'Error al guardar token de usuario',
            details: err.message,
            code: err.code,
            debug_id: debugId,
        });
    }
};

app.post('/api/user-api-token', requireMondaySession, saveUserApiTokenHandler);
app.post('/api/user-api-token-v2', requireMondaySession, saveUserApiTokenHandler);

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
        item_id,
        item_snapshot,
        issue_in_afip
    } = req.body;

    const accountId = String(monday_account_id || req.mondayIdentity.accountId || '');
    const boardId = String(board_id || '').trim();
    const itemId = String(item_id || '').trim();

    if (!accountId || !boardId || !itemId) {
        return res.status(400).json({ error: 'monday_account_id, board_id e item_id son obligatorios' });
    }

    if (!item_snapshot || !Array.isArray(item_snapshot.main_columns) || !Array.isArray(item_snapshot.subitems)) {
        return res.status(400).json({
            error: 'Falta item_snapshot con columnas de item y subitems para procesar Factura C'
        });
    }

    if (!ensureAccountMatch(req, res, accountId)) return;

    try {
        const company = await getCompanyByMondayAccountId(accountId);
        if (!company) {
            return res.status(404).json({ error: 'Empresa no encontrada para la cuenta monday' });
        }

        await ensureInvoiceEmissionsTable();

        const existingEmission = await db.query(
            `SELECT id, status, afip_result_json, pdf_base64, updated_at
             FROM invoice_emissions
             WHERE company_id = $1
               AND board_id = $2
               AND item_id = $3
               AND invoice_type = 'C'
             LIMIT 1`,
            [company.id, boardId, itemId]
        );

        if (existingEmission.rows.length > 0 && existingEmission.rows[0].status === 'success') {
            return res.status(409).json({
                error: 'Este item ya fue emitido como Factura C',
                emission: existingEmission.rows[0],
            });
        }

        await db.query(
            `INSERT INTO invoice_emissions (company_id, board_id, item_id, invoice_type, status, request_json)
             VALUES ($1, $2, $3, 'C', 'processing', $4)
             ON CONFLICT (company_id, board_id, item_id, invoice_type)
             DO UPDATE SET
               status = 'processing',
               request_json = EXCLUDED.request_json,
               error_message = NULL,
               updated_at = CURRENT_TIMESTAMP`,
            [company.id, boardId, itemId, JSON.stringify(req.body || {})]
        );

        const certResult = await db.query(
            'SELECT id, crt_file_url, encrypted_private_key FROM afip_credentials WHERE company_id = $1 LIMIT 1',
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

        const mainColumns = item_snapshot.main_columns || [];
        const subitems = item_snapshot.subitems || [];

        const fechaEmisionRaw = getColumnTextById(mainColumns, mapping.fecha_emision);
        const receptorCuit = getColumnTextById(mainColumns, mapping.receptor_cuit) || null;

        const rawLines = subitems.map((subitem) => ({
            subitem_id: Number(subitem.id || 0),
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

        let afipResult = null;
        let pdfBase64 = null;
        let pdfBuffer = null;
        let mondayUpload = null;
        const shouldIssueInAfip = issue_in_afip !== false;
        if (shouldIssueInAfip) {
            const certRow = certResult.rows[0];
            const certPem = normalizePem(certRow.crt_file_url, 'CERTIFICATE');
            const decryptedPrivateKey = CryptoJS.AES.decrypt(
                certRow.encrypted_private_key,
                process.env.ENCRYPTION_KEY
            ).toString(CryptoJS.enc.Utf8);
            const keyPem = normalizePem(decryptedPrivateKey, 'PRIVATE KEY');

            if (!certPem || !keyPem) {
                throw new Error('No se pudieron leer certificados para autenticación AFIP');
            }

            const { token, sign } = await afipLoginCms(certPem, keyPem);
            afipResult = await afipIssueFacturaC({
                token,
                sign,
                cuit: company.cuit,
                pointOfSale: company.default_point_of_sale,
                draft: facturaCDraft,
            });

            if (afipResult?.cae) {
                pdfBuffer = await generateFacturaCPdfBuffer({
                    company,
                    draft: facturaCDraft,
                    afipResult,
                    itemId,
                });
                pdfBase64 = pdfBuffer.toString('base64');
            }
        }

        if (pdfBuffer) {
            const mondayUserToken = await getStoredMondayUserApiToken({
                mondayAccountId: accountId,
            });
            const invoicePdfColumnId = await getInvoicePdfColumnId({
                companyId: company.id,
                boardId,
            });

            if (mondayUserToken && invoicePdfColumnId) {
                try {
                    mondayUpload = await uploadPdfToMondayFileColumn({
                        apiToken: mondayUserToken,
                        itemId,
                        fileColumnId: invoicePdfColumnId,
                        pdfBuffer,
                        filename: `Factura-C-${itemId}.pdf`,
                    });
                } catch (uploadErr) {
                    mondayUpload = {
                        uploaded: false,
                        reason: 'upload_failed',
                        details: uploadErr.message,
                    };
                }
            } else {
                mondayUpload = {
                    uploaded: false,
                    reason: !mondayUserToken ? 'missing_user_api_token' : 'missing_invoice_pdf_column',
                };
            }
        }

        await db.query(
            `UPDATE invoice_emissions
             SET status = $5,
                 draft_json = $6,
                 afip_result_json = $7,
                 pdf_base64 = $8,
                 updated_at = CURRENT_TIMESTAMP
             WHERE company_id = $1
               AND board_id = $2
               AND item_id = $3
               AND invoice_type = 'C'`,
            [
                company.id,
                boardId,
                itemId,
                afipResult?.cae ? 'success' : 'prepared',
                JSON.stringify(facturaCDraft),
                JSON.stringify(afipResult || null),
                pdfBase64,
            ]
        );

        return res.status(202).json({
            message: afipResult ? 'Factura C emitida en AFIP desde backend' : 'Factura C preparada en backend',
            item_id: Number(itemId),
            board_id: Number(boardId),
            draft: facturaCDraft,
            status_flow: COMPROBANTE_STATUS_FLOW,
            afip_result: afipResult,
            pdf_base64: pdfBase64,
            monday_upload: mondayUpload,
        });
    } catch (err) {
        console.error('❌ Error al preparar Factura C en backend:', err);
        try {
            const company = await getCompanyByMondayAccountId(accountId);
            if (company) {
                await ensureInvoiceEmissionsTable();
                await db.query(
                    `UPDATE invoice_emissions
                     SET status = 'error',
                         error_message = $4,
                         updated_at = CURRENT_TIMESTAMP
                     WHERE company_id = $1
                       AND board_id = $2
                       AND item_id = $3
                       AND invoice_type = 'C'`,
                    [company.id, boardId, itemId, err.message]
                );
            }
        } catch (persistErr) {
            console.error('❌ Error guardando estado de error en invoice_emissions:', persistErr);
        }

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
