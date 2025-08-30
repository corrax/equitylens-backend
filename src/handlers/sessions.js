const AWS = require('aws-sdk')
const { randomUUID, randomBytes } = require('crypto')
const { PDFDocument } = require('pdf-lib')
const parser = require('lambda-multipart-parser')

const ddb = new AWS.DynamoDB.DocumentClient()
const s3 = new AWS.S3({ signatureVersion: 'v4' })
const TABLE = process.env.TABLE_NAME
const BUCKET = process.env.BUCKET_NAME
const RL_TABLE = process.env.RATE_LIMITS_TABLE
const RL_IP_LIMIT = Number(process.env.RATE_LIMIT_IP_DAILY || 50)
const RL_SESSION_LIMIT = Number(process.env.RATE_LIMIT_SESSION_DAILY || 10)

function response(statusCode, body) {
  return {
    statusCode,
    headers: {
      'Content-Type': 'application/json',
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Headers': '*',
      'Access-Control-Allow-Methods': '*',
    },
    body: JSON.stringify(body)
  }
}

function getIp(event) {
  return (
    event?.requestContext?.identity?.sourceIp ||
    event?.requestContext?.http?.sourceIp ||
    event?.headers?.['x-forwarded-for']?.split(',')?.[0]?.trim() ||
    '0.0.0.0'
  )
}

function getSessionHeader(event) {
  const h = event?.headers || {}
  return h['X-EquityLens-Session'] || h['x-equitylens-session'] || ''
}

function yyyymmdd(d = new Date()) {
  const y = d.getUTCFullYear()
  const m = String(d.getUTCMonth() + 1).padStart(2, '0')
  const day = String(d.getUTCDate()).padStart(2, '0')
  return `${y}${m}${day}`
}

async function rateLimitCheck(event, { cost = 1 } = {}) {
  if (!RL_TABLE) return { ok: true }
  const day = yyyymmdd()
  const ip = getIp(event)
  const sid = getSessionHeader(event)
  const now = Math.floor(Date.now() / 1000)
  // TTL midnight+1 day
  const ttl = now + 86400
  const checks = []
  if (RL_IP_LIMIT > 0) checks.push({ key: `ip:${ip}:${day}`, limit: RL_IP_LIMIT })
  if (sid && RL_SESSION_LIMIT > 0) checks.push({ key: `sid:${sid}:${day}`, limit: RL_SESSION_LIMIT })
  for (const c of checks) {
    const res = await ddb.update({
      TableName: RL_TABLE,
      Key: { k: c.key },
      UpdateExpression: 'SET cnt = if_not_exists(cnt, :z) + :inc, expiresAt = if_not_exists(expiresAt, :ttl)',
      ExpressionAttributeValues: { ':z': 0, ':inc': cost, ':ttl': ttl },
      ReturnValues: 'UPDATED_NEW'
    }).promise()
    const count = Number(res?.Attributes?.cnt || 0)
    if (count > c.limit) {
      return { ok: false, scope: c.key.startsWith('ip:') ? 'ip' : 'session', limit: c.limit, count }
    }
  }
  return { ok: true }
}

async function createSession(event) {
  const rl = await rateLimitCheck(event, { cost: 1 })
  if (!rl.ok) return response(429, { message: 'Rate limit exceeded', scope: rl.scope, limit: rl.limit, count: rl.count })
  const now = new Date().toISOString()
  const sessionId = randomUUID()
  const body = JSON.parse(event.body || '{}')
  const contentType = body.contentType || 'application/octet-stream'
  const key = `${sessionId}/original`
  const url = s3.getSignedUrl('putObject', { Bucket: BUCKET, Key: key, Expires: 900, ContentType: contentType })
  await ddb.put({ TableName: TABLE, Item: { sessionId, createdAt: now, status: 'CREATED', keyOriginal: key } }).promise()
  return response(201, { sessionId, uploadUrl: url, key })
}

function newToken() {
  return randomUUID() + '-' + randomBytes(8).toString('hex')
}

async function putFields(event) {
  const { id } = event.pathParameters || {}
  if (!id) return response(400, { message: 'Missing session id' })
  const body = JSON.parse(event.body || '{}')
  const signers = Array.isArray(body.signers) ? body.signers : []
  const fields = Array.isArray(body.fields) ? body.fields : []
  // assign tokens to signers if missing
  const signersWithTokens = signers.map(s => ({ ...s, token: s.token || newToken(), status: s.status || 'PENDING' }))
  await ddb.update({
    TableName: TABLE,
    Key: { sessionId: id },
    UpdateExpression: 'SET signers = :s, fields = :f, updatedAt = :u',
    ExpressionAttributeValues: { ':s': signersWithTokens, ':f': fields, ':u': new Date().toISOString() },
  }).promise()
  return response(200, { ok: true })
}

async function prepare(event) {
  const { id } = event.pathParameters || {}
  if (!id) return response(400, { message: 'Missing session id' })
  // Load session
  const res = await ddb.get({ TableName: TABLE, Key: { sessionId: id } }).promise()
  const item = res?.Item
  if (!item) return response(404, { message: 'Not found' })
  let key = item.keyOriginal
  if (!key) return response(400, { message: 'No original document' })
  // Convert DOCX/DOC to PDF if needed
  if (!/\.pdf$/i.test(key)) {
    try {
      const lambda = new AWS.Lambda()
      const inv = await lambda.invoke({
        FunctionName: process.env.CONVERT_FUNCTION_NAME,
        InvocationType: 'RequestResponse',
        Payload: JSON.stringify({ key })
      }).promise()
      const payload = inv?.Payload ? JSON.parse(inv.Payload.toString()) : null
      if (payload && payload.statusCode === 200) {
        const body = JSON.parse(payload.body || '{}')
        if (body.keyPdf) key = body.keyPdf
      } else {
        return response(payload?.statusCode || 500, { message: 'Conversion failed', detail: payload?.body })
      }
    } catch (e) {
      console.error('Conversion invoke failed', e)
      return response(500, { message: 'Conversion failed', detail: e.message })
    }
  }
  // Fetch PDF
  const obj = await s3.getObject({ Bucket: BUCKET, Key: key }).promise()
  const pdfBytes = obj.Body instanceof Buffer ? obj.Body : Buffer.from(obj.Body)
  const pdfDoc = await PDFDocument.load(pdfBytes)
  const form = pdfDoc.getForm()
  const fields = Array.isArray(item.fields) ? item.fields : []
  for (const f of fields) {
    if (!f || !f.page || f.type !== 'signature') continue
    const pIndex = Math.max(0, Number(f.page) - 1)
    const pages = pdfDoc.getPages()
    if (pIndex >= pages.length) continue
    const page = pages[pIndex]
    const name = `sig_${String(f.signerId || 'x')}_${String(f.id || Math.random().toString(36).slice(2))}`
    const sig = form.createSignature(name)
    sig.addToPage(page, { x: Number(f.x)||0, y: Number(f.y)||0, width: Math.max(10, Number(f.w)||10), height: Math.max(10, Number(f.h)||10) })
  }
  const out = await pdfDoc.save()
  const keyPrepared = `${id}/prepared.pdf`
  await s3.putObject({ Bucket: BUCKET, Key: keyPrepared, Body: Buffer.from(out), ContentType: 'application/pdf' }).promise()
  await ddb.update({
    TableName: TABLE,
    Key: { sessionId: id },
    UpdateExpression: 'SET status = :st, keyPrepared = :kp, updatedAt = :u',
    ExpressionAttributeValues: { ':st': 'PREPARED', ':kp': keyPrepared, ':u': new Date().toISOString() },
  }).promise()
  const getUrl = s3.getSignedUrl('getObject', { Bucket: BUCKET, Key: keyPrepared, Expires: 900 })
  return response(202, { ok: true, preparedUrl: getUrl })
}

async function start(event) {
  const { id } = event.pathParameters || {}
  if (!id) return response(400, { message: 'Missing session id' })
  const ses = new AWS.SES({ apiVersion: '2010-12-01' })
  const portal = process.env.SIGNER_PORTAL_URL || ''
  const sender = process.env.SENDER_EMAIL || ''
  const get = await ddb.get({ TableName: TABLE, Key: { sessionId: id } }).promise()
  const item = get?.Item
  if (!item) return response(404, { message: 'Not found' })
  const signers = item.signers || []
  for (const s of signers) {
    if (!s?.email || !s?.token) continue
    const link = `${portal.replace(/\/$/,'')}/#/sign/${encodeURIComponent(id)}/${encodeURIComponent(s.token)}`
    try {
      await ses.sendEmail({
        Source: sender,
        Destination: { ToAddresses: [s.email] },
        Message: {
          Subject: { Data: `Signature request for ${id}` },
          Body: {
            Html: { Data: `<p>Hello ${s.name || ''},</p><p>You have a document to sign.</p><p><a href="${link}">Open signer portal</a></p>` },
            Text: { Data: `Hello ${s.name || ''}\n\nOpen signer portal: ${link}` }
          }
        }
      }).promise()
    } catch (e) {
      console.error('SES sendEmail failed', e)
    }
  }
  await ddb.update({
    TableName: TABLE,
    Key: { sessionId: id },
    UpdateExpression: 'SET status = :st, updatedAt = :u',
    ExpressionAttributeValues: { ':st': 'IN_PROGRESS', ':u': new Date().toISOString() },
  }).promise()
  return response(202, { ok: true })
}

async function getSession(event) {
  const { id } = event.pathParameters || {}
  if (!id) return response(400, { message: 'Missing session id' })
  const res = await ddb.get({ TableName: TABLE, Key: { sessionId: id } }).promise()
  if (!res || !res.Item) return response(404, { message: 'Not found' })
  return response(200, res.Item)
}

async function download(event) {
  const { id } = event.pathParameters || {}
  if (!id) return response(400, { message: 'Missing session id' })
  const res = await ddb.get({ TableName: TABLE, Key: { sessionId: id } }).promise()
  if (!res || !res.Item) return response(404, { message: 'Not found' })
  const key = res.Item.keySigned || res.Item.keyPrepared || res.Item.keyOriginal
  if (!key) return response(404, { message: 'No document available' })
  const url = s3.getSignedUrl('getObject', { Bucket: BUCKET, Key: key, Expires: 900 })
  return response(200, { url })
}

async function getSigner(event) {
  const { id, token } = event.pathParameters || {}
  if (!id || !token) return response(400, { message: 'Missing params' })
  const res = await ddb.get({ TableName: TABLE, Key: { sessionId: id } }).promise()
  const item = res?.Item
  if (!item) return response(404, { message: 'Not found' })
  const signer = (item.signers || []).find(s => s.token === token)
  if (!signer) return response(404, { message: 'Invalid token' })
  const key = item.keyPrepared || item.keyOriginal
  const url = key ? s3.getSignedUrl('getObject', { Bucket: BUCKET, Key: key, Expires: 900 }) : null
  const fields = (item.fields || []).filter(f => f.signerId === signer.id)
  return response(200, { sessionId: id, signer: { id: signer.id, name: signer.name, email: signer.email, order: signer.order, status: signer.status }, fields, docUrl: url })
}

async function approveSigner(event) {
  const { id, token } = event.pathParameters || {}
  if (!id || !token) return response(400, { message: 'Missing params' })
  const res = await ddb.get({ TableName: TABLE, Key: { sessionId: id } }).promise()
  const item = res?.Item
  if (!item) return response(404, { message: 'Not found' })
  const signers = item.signers || []
  const idx = signers.findIndex(s => s.token === token)
  if (idx === -1) return response(404, { message: 'Invalid token' })
  signers[idx].status = 'APPROVED'
  signers[idx].approvedAt = new Date().toISOString()
  await ddb.update({
    TableName: TABLE,
    Key: { sessionId: id },
    UpdateExpression: 'SET signers = :s, updatedAt = :u',
    ExpressionAttributeValues: { ':s': signers, ':u': new Date().toISOString() }
  }).promise()
  // If all signers approved, trigger signing function
  const allApproved = signers.length > 0 && signers.every(s => s.status === 'APPROVED')
  if (allApproved) {
    const lambda = new AWS.Lambda()
    const key = item.keyPrepared || item.keyOriginal
    if (key) {
      try {
        await lambda.invoke({
          FunctionName: process.env.SIGN_FUNCTION_NAME,
          InvocationType: 'Event',
          Payload: JSON.stringify({ sessionId: id, key })
        }).promise()
      } catch (e) {
        console.error('Invoke sign function failed', e)
      }
    }
  }
  return response(200, { ok: true, allApproved })
}

async function convertLegacyDoc(event) {
  const form = await parser.parse(event)
  const file = form.files?.[0]
  if (!file) return response(400, { message: 'No file uploaded' })

  try {
    const lambda = new AWS.Lambda()
    const inv = await lambda.invoke({
      FunctionName: process.env.CONVERT_FUNCTION_NAME,
      InvocationType: 'RequestResponse',
      Payload: JSON.stringify({
        // Pass raw file buffer to the conversion lambda
        file: file.content.toString('base64'),
        filename: file.filename,
      })
    }).promise()

    const payload = inv?.Payload ? JSON.parse(inv.Payload.toString()) : null
    if (payload && payload.statusCode === 200) {
      const body = JSON.parse(payload.body || '{}')
      return {
        statusCode: 200,
        headers: { 'Content-Type': 'application/pdf' },
        body: body.pdf, // Assuming the lambda returns base64 pdf
        isBase64Encoded: true,
      }
    } else {
      return response(payload?.statusCode || 500, { message: 'Conversion failed', detail: payload?.body })
    }
  } catch (e) {
    console.error('Conversion invoke failed', e)
    return response(500, { message: 'Conversion failed', detail: e.message })
  }
}

async function router(event) {
  const { resource, httpMethod } = event
  try {
    if (resource === '/sessions' && httpMethod === 'POST') return await createSession(event)
    if (resource === '/sessions/{id}/fields' && httpMethod === 'PUT') return await putFields(event)
    if (resource === '/sessions/{id}/prepare' && httpMethod === 'POST') return await prepare(event)
    if (resource === '/sessions/{id}/start' && httpMethod === 'POST') return await start(event)
    if (resource === '/sessions/{id}' && httpMethod === 'GET') return await getSession(event)
    if (resource === '/sessions/{id}/download' && httpMethod === 'GET') return await download(event)
    if (resource === '/sessions/{id}/signers/{token}' && httpMethod === 'GET') return await getSigner(event)
    if (resource === '/sessions/{id}/signers/{token}/approve' && httpMethod === 'POST') return await approveSigner(event)
    if (resource === '/limits' && httpMethod === 'GET') {
      // Report remaining allowance
      const day = yyyymmdd()
      const ip = getIp(event)
      const sid = getSessionHeader(event)
      const keys = [
        RL_IP_LIMIT > 0 ? { scope: 'ip', key: `ip:${ip}:${day}`, limit: RL_IP_LIMIT } : null,
        (sid && RL_SESSION_LIMIT > 0) ? { scope: 'session', key: `sid:${sid}:${day}`, limit: RL_SESSION_LIMIT } : null,
      ].filter(Boolean)
      const results = {}
      for (const k of keys) {
        try {
          const g = await ddb.get({ TableName: RL_TABLE, Key: { k: k.key } }).promise()
          const cnt = Number(g?.Item?.cnt || 0)
          results[k.scope] = { limit: k.limit, used: cnt, remaining: Math.max(0, k.limit - cnt) }
        } catch (e) {
          // If the key doesn't exist, default to 0 used
          results[k.scope] = { limit: k.limit, used: 0, remaining: k.limit }
        }
      }
      return response(200, { window: 'daily', ...results })
    }
    return response(404, { message: 'Not found' })
  } catch (e) {
    console.error(e)
    return response(500, { message: 'Internal error', detail: e.message })
  }
}

module.exports.router = router
