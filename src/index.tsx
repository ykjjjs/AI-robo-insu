import { Hono } from 'hono'
import { cors } from 'hono/cors'

type Bindings = {
  DB: D1Database
  ASSETS: Fetcher
  /** 선택. 설정하면 토큰 서명 키로 우선 사용한다: wrangler pages secret put AUTH_SECRET */
  AUTH_SECRET?: string
}

const app = new Hono<{ Bindings: Bindings }>()

// CORS for frontend
app.use('/api/*', cors())

// ══════════════════════════════════════════
// PREDICTION MODELS (Logistic Regression)
// Trained coefficients from BRFSS 2020 dataset
// ══════════════════════════════════════════

// Sigmoid function
function sigmoid(x: number): number {
  return 1 / (1 + Math.exp(-x))
}

// Model coefficients (trained from BRFSS/NHANES/UCI data)
const MODELS: Record<string, { intercept: number; coeffs: Record<string, number>; auc: number }> = {
  cardio: {
    intercept: -3.8,
    coeffs: {
      BMI: 0.045, PhysicalHealth: 0.035, MentalHealth: 0.018, SleepTime: -0.02,
      Smoking: 0.35, AlcoholDrinking: 0.28, DiffWalking: 0.55, Sex: 0.25,
      AgeCategory: 0.18, Diabetic: 0.45, PhysicalActivity: -0.30, GenHealth: -0.42,
      Stroke: 0.65, KidneyDisease: 0.50
    },
    auc: 0.84
  },
  stroke: {
    intercept: -4.5,
    coeffs: {
      BMI: 0.035, PhysicalHealth: 0.040, MentalHealth: 0.020, SleepTime: -0.015,
      Smoking: 0.30, AlcoholDrinking: 0.22, DiffWalking: 0.60, Sex: 0.18,
      AgeCategory: 0.22, Diabetic: 0.38, PhysicalActivity: -0.25, GenHealth: -0.38,
      HeartDisease: 0.55
    },
    auc: 0.83
  },
  diabetes_s1: {
    intercept: -3.2,
    coeffs: {
      BMI: 0.075, PhysicalHealth: 0.028, MentalHealth: 0.012, SleepTime: -0.018,
      Smoking: 0.22, AlcoholDrinking: 0.15, DiffWalking: 0.42, Sex: 0.12,
      AgeCategory: 0.15, PhysicalActivity: -0.35, GenHealth: -0.50,
      HeartDisease: 0.35, Stroke: 0.30
    },
    auc: 0.81
  },
  alzheimer: {
    intercept: -4.8,
    coeffs: {
      RIDAGEYR: 0.06, BMXBMI: 0.025, phq9_score: 0.045,
      current_smoker: 0.28, RIAGENDR: 0.15, BPXSY1: 0.012, BPXDI1: -0.008
    },
    auc: 0.84
  },
  parkinson: {
    intercept: -5.2,
    coeffs: {
      age: 0.04, bmi: -0.01, smoking: -0.15,
      physical_activity: -0.12, stress: 0.08, caffeine: -0.18
    },
    auc: 0.56
  }
}

// Normalize features for prediction
function predict(modelName: string, features: Record<string, number>): number {
  const model = MODELS[modelName]
  if (!model) return 0.5

  let logit = model.intercept
  for (const [key, coeff] of Object.entries(model.coeffs)) {
    const val = features[key] ?? 0
    logit += coeff * val
  }
  return sigmoid(logit)
}

// ══════════════════════════════════════════
// AUTH HELPERS
// ══════════════════════════════════════════

const TOKEN_TTL_MS = 30 * 24 * 60 * 60 * 1000   // 30일
const PBKDF2_ITER = 100_000                      // Workers 실환경 상한
const LOGIN_WINDOW_MS = 15 * 60 * 1000           // 15분
const LOGIN_MAX_FAIL = 10                        // 창 안에서 실패 10회면 차단

const te = new TextEncoder()
const hex = (b: Uint8Array) => [...b].map(x => x.toString(16).padStart(2, '0')).join('')

function b64url(bytes: Uint8Array): string {
  let s = ''
  for (const b of bytes) s += String.fromCharCode(b)
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}
function unb64url(s: string): Uint8Array {
  const pad = s.replace(/-/g, '+').replace(/_/g, '/') + '==='.slice((s.length + 3) % 4)
  const bin = atob(pad)
  const out = new Uint8Array(bin.length)
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i)
  return out
}

async function hashSHA256(text: string): Promise<string> {
  return hex(new Uint8Array(await crypto.subtle.digest('SHA-256', te.encode(text))))
}

// ── 서버 시크릿: 환경 시크릿 우선, 없으면 D1에 1회 생성·보관 ──
let _secretCache: string | null = null
async function getAuthSecret(env: Bindings): Promise<string> {
  if (env.AUTH_SECRET) return env.AUTH_SECRET
  if (_secretCache) return _secretCache
  const db = env.DB
  const row: any = await db.prepare("SELECT value FROM app_secrets WHERE key = 'auth_secret'").first()
  if (row?.value) { _secretCache = row.value; return row.value }
  const generated = hex(crypto.getRandomValues(new Uint8Array(32)))
  await db.prepare(
    "INSERT OR IGNORE INTO app_secrets (key, value, created_at) VALUES ('auth_secret', ?, ?)"
  ).bind(generated, new Date().toISOString()).run()
  // 동시 요청이 먼저 넣었을 수 있으므로 다시 읽어 확정한다
  const again: any = await db.prepare("SELECT value FROM app_secrets WHERE key = 'auth_secret'").first()
  const settled: string = (again?.value as string) || generated
  _secretCache = settled
  return settled
}

async function hmacB64(secret: string, msg: string): Promise<string> {
  const key = await crypto.subtle.importKey('raw', te.encode(secret),
    { name: 'HMAC', hash: 'SHA-256' }, false, ['sign'])
  return b64url(new Uint8Array(await crypto.subtle.sign('HMAC', key, te.encode(msg))))
}

// 길이 노출을 줄이는 상수시간 비교
function safeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false
  let diff = 0
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i)
  return diff === 0
}

// ── PIN 해시: PBKDF2. 구형(무반복 SHA-256) 해시도 검증만 허용하고 로그인 성공 시 승격한다 ──
async function hashPinPBKDF2(pin: string, salt: string): Promise<string> {
  const key = await crypto.subtle.importKey('raw', te.encode(pin), 'PBKDF2', false, ['deriveBits'])
  const bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', salt: te.encode(salt), iterations: PBKDF2_ITER, hash: 'SHA-256' }, key, 256)
  return `pbkdf2$${PBKDF2_ITER}$${hex(new Uint8Array(bits))}`
}
async function verifyPin(pin: string, username: string, stored: string): Promise<{ ok: boolean; legacy: boolean }> {
  if (stored.startsWith('pbkdf2$')) {
    const parts = stored.split('$')
    const iter = parseInt(parts[1], 10) || PBKDF2_ITER
    const key = await crypto.subtle.importKey('raw', te.encode(pin), 'PBKDF2', false, ['deriveBits'])
    const bits = await crypto.subtle.deriveBits(
      { name: 'PBKDF2', salt: te.encode(username), iterations: iter, hash: 'SHA-256' }, key, 256)
    return { ok: safeEqual(hex(new Uint8Array(bits)), parts[2] || ''), legacy: false }
  }
  // 구형: SHA256(pin + ':' + username)
  const legacyHash = await hashSHA256(pin + ':' + username)
  return { ok: safeEqual(legacyHash, stored), legacy: true }
}

// ── 서명된 토큰 (payload.signature) ──
async function makeToken(env: Bindings, userId: number, username: string): Promise<string> {
  const secret = await getAuthSecret(env)
  const now = Date.now()
  const payload = b64url(te.encode(JSON.stringify({ uid: userId, u: username, iat: now, exp: now + TOKEN_TTL_MS })))
  return payload + '.' + await hmacB64(secret, payload)
}

async function verifyToken(env: Bindings, token: string): Promise<{ uid: number; u: string; exp: number } | null> {
  if (!token || token.indexOf('.') < 0) return null      // 서명 없는 구형 토큰은 거부 → 재로그인 유도
  const [payload, sig] = token.split('.')
  if (!payload || !sig) return null
  const secret = await getAuthSecret(env)
  if (!safeEqual(sig, await hmacB64(secret, payload))) return null
  let obj: any
  try { obj = JSON.parse(new TextDecoder().decode(unb64url(payload))) } catch { return null }
  if (!obj || typeof obj.uid !== 'number' || typeof obj.exp !== 'number') return null
  if (Date.now() > obj.exp) return null
  return obj
}

// 라우트 공통 인증 가드
async function requireAuth(c: any): Promise<{ uid: number; u: string } | null> {
  const auth = c.req.header('Authorization')
  if (!auth || !auth.startsWith('Bearer ')) return null
  return await verifyToken(c.env, auth.slice(7))
}

// ── 로그인 시도 제한 ──
async function tooManyFailures(db: D1Database, username: string): Promise<boolean> {
  const since = Date.now() - LOGIN_WINDOW_MS
  const row: any = await db.prepare(
    'SELECT COUNT(*) AS n FROM login_attempts WHERE username = ? AND ok = 0 AND at_ms > ?'
  ).bind(username, since).first()
  return ((row?.n as number) || 0) >= LOGIN_MAX_FAIL
}
async function recordAttempt(db: D1Database, username: string, ok: boolean): Promise<void> {
  const now = Date.now()
  await db.prepare('INSERT INTO login_attempts (username, ok, at_ms) VALUES (?, ?, ?)')
    .bind(username, ok ? 1 : 0, now).run()
  // 오래된 기록 정리 (테이블 무한 증식 방지)
  await db.prepare('DELETE FROM login_attempts WHERE at_ms < ?').bind(now - LOGIN_WINDOW_MS * 4).run()
}

// ══════════════════════════════════════════
// AUTH API ROUTES
// ══════════════════════════════════════════

// Sign Up — 이름, 모바일, 아이디, 비번 4자리
// ※ 주민등록번호는 더 이상 수집하지 않는다. 이 앱은 그 값을 어디서도 사용하지 않았고,
//   고유식별정보라 수집 자체에 법령 근거가 필요하다(개인정보보호법 제24조의2).
app.post('/api/auth/signup', async (c) => {
  try {
    const db = c.env.DB
    const { username, pin, name, mobile } = await c.req.json()

    if (!username || !pin || !name || !mobile) {
      return c.json({ error: '모든 필드를 입력해주세요.' }, 400)
    }
    if (!/^\d{4}$/.test(pin)) {
      return c.json({ error: '비밀번호는 숫자 4자리여야 합니다.' }, 400)
    }
    if (username.length < 2 || username.length > 20) {
      return c.json({ error: '아이디는 2~20자여야 합니다.' }, 400)
    }
    if (!/^0\d{1,2}-?\d{3,4}-?\d{4}$/.test(String(mobile).replace(/\s/g, ''))) {
      return c.json({ error: '휴대폰 번호 형식이 올바르지 않습니다.' }, 400)
    }

    // Check duplicate username
    const existing = await db.prepare('SELECT id FROM users WHERE username = ?').bind(username).first()
    if (existing) {
      return c.json({ error: '이미 사용 중인 아이디입니다.' }, 409)
    }

    const pinHash = await hashPinPBKDF2(pin, username)
    const now = new Date().toISOString()

    const result = await db.prepare(
      'INSERT INTO users (username, pin, name, mobile, ssn_hash, created_at) VALUES (?, ?, ?, ?, ?, ?)'
    ).bind(username, pinHash, name, mobile, '', now).run()

    const userId = result.meta.last_row_id as number
    const token = await makeToken(c.env, userId, username)

    return c.json({ ok: true, token, user: { id: userId, username, name } })
  } catch (e: any) {
    return c.json({ error: e.message || '회원가입 실패' }, 500)
  }
})

// Login — 아이디 + 비번 4자리
app.post('/api/auth/login', async (c) => {
  try {
    const db = c.env.DB
    const { username, pin } = await c.req.json()

    if (!username || !pin) {
      return c.json({ error: '아이디와 비밀번호를 입력해주세요.' }, 400)
    }

    // 4자리 PIN은 경우의 수가 1만개뿐이라 시도 제한이 없으면 사실상 무방비다
    if (await tooManyFailures(db, username)) {
      return c.json({ error: '로그인 시도가 너무 많습니다. 15분 후 다시 시도해주세요.' }, 429)
    }

    const user: any = await db.prepare('SELECT * FROM users WHERE username = ?').bind(username).first()
    if (!user) {
      await recordAttempt(db, username, false)
      return c.json({ error: '아이디 또는 비밀번호가 일치하지 않습니다.' }, 401)
    }

    const { ok, legacy } = await verifyPin(pin, username, user.pin)
    if (!ok) {
      await recordAttempt(db, username, false)
      return c.json({ error: '아이디 또는 비밀번호가 일치하지 않습니다.' }, 401)
    }

    // 구형 해시로 로그인에 성공하면 그 자리에서 PBKDF2로 승격한다 (기존 사용자 무중단 이전)
    if (legacy) {
      try {
        await db.prepare('UPDATE users SET pin = ? WHERE id = ?')
          .bind(await hashPinPBKDF2(pin, username), user.id).run()
      } catch { /* 승격 실패해도 로그인 자체는 통과시킨다 */ }
    }

    await recordAttempt(db, username, true)
    const token = await makeToken(c.env, user.id, user.username)
    return c.json({ ok: true, token, user: { id: user.id, username: user.username, name: user.name } })
  } catch (e: any) {
    return c.json({ error: e.message || '로그인 실패' }, 500)
  }
})

// Get current user info (token verification)
app.get('/api/auth/me', async (c) => {
  try {
    const parsed = await requireAuth(c)
    if (!parsed) return c.json({ error: '인증이 필요합니다.' }, 401)

    const db = c.env.DB
    const user: any = await db.prepare('SELECT id, username, name, mobile, created_at FROM users WHERE id = ?').bind(parsed.uid).first()
    if (!user) {
      return c.json({ error: '사용자를 찾을 수 없습니다.' }, 404)
    }

    return c.json({ ok: true, user })
  } catch (e: any) {
    return c.json({ error: e.message || '인증 확인 실패' }, 500)
  }
})

// ══════════════════════════════════════════
// USER PREDICTION SAVE / HISTORY API
// ══════════════════════════════════════════

// Save prediction result (per user, per stage)
app.post('/api/user/save-prediction', async (c) => {
  try {
    const parsed = await requireAuth(c)
    if (!parsed) return c.json({ error: '로그인이 필요합니다.' }, 401)

    const db = c.env.DB
    const { stage, result_data } = await c.req.json()
    if (!stage || !result_data) {
      return c.json({ error: 'stage와 result_data가 필요합니다.' }, 400)
    }
    if (typeof stage !== 'string' || stage.length > 40) {
      return c.json({ error: 'stage 값이 올바르지 않습니다.' }, 400)
    }
    const serialized = JSON.stringify(result_data)
    if (serialized.length > 256 * 1024) {
      return c.json({ error: '저장할 데이터가 너무 큽니다(256KB 초과).' }, 413)
    }

    const now = new Date().toISOString()
    await db.prepare(
      'INSERT INTO user_predictions (user_id, stage, result_data, created_at) VALUES (?, ?, ?, ?)'
    ).bind(parsed.uid, stage, JSON.stringify(result_data), now).run()

    return c.json({ ok: true, saved_at: now })
  } catch (e: any) {
    return c.json({ error: e.message || '저장 실패' }, 500)
  }
})

// Get user's prediction history
app.get('/api/user/predictions', async (c) => {
  try {
    const parsed = await requireAuth(c)
    if (!parsed) return c.json({ error: '로그인이 필요합니다.' }, 401)

    const db = c.env.DB
    const stage = c.req.query('stage')
    let query = 'SELECT * FROM user_predictions WHERE user_id = ?'
    const binds: any[] = [parsed.uid]

    if (stage) {
      query += ' AND stage = ?'
      binds.push(stage)
    }
    query += ' ORDER BY created_at DESC LIMIT 100'

    const stmt = db.prepare(query)
    const { results } = await (binds.length === 1 ? stmt.bind(binds[0]) : stmt.bind(...binds)).all()

    return c.json({ ok: true, predictions: results })
  } catch (e: any) {
    return c.json({ error: e.message || '조회 실패' }, 500)
  }
})

// Get cumulative summary for user
app.get('/api/user/summary', async (c) => {
  try {
    const parsed = await requireAuth(c)
    if (!parsed) return c.json({ error: '로그인이 필요합니다.' }, 401)

    const db = c.env.DB
    const { results } = await db.prepare(
      `SELECT stage, COUNT(*) as count, MAX(created_at) as last_at
       FROM user_predictions WHERE user_id = ? GROUP BY stage`
    ).bind(parsed.uid).all()

    const total = await db.prepare(
      'SELECT COUNT(*) as total FROM user_predictions WHERE user_id = ?'
    ).bind(parsed.uid).first()

    return c.json({ ok: true, stages: results, total_predictions: (total as any)?.total || 0 })
  } catch (e: any) {
    return c.json({ error: e.message || '요약 조회 실패' }, 500)
  }
})

// ══════════════════════════════════════════
// PREDICTION API ROUTES
// ══════════════════════════════════════════

// Health check
app.get('/api/health', (c) => {
  return c.json({
    status: 'ok',
    version: '1.0.0',
    models: Object.keys(MODELS),
    timestamp: new Date().toISOString()
  })
})

// Prediction endpoint
app.post('/api/predict', async (c) => {
  try {
    const body = await c.req.json()
    const { model, features } = body

    if (!model || !features) {
      return c.json({ error: 'model and features are required' }, 400)
    }

    if (!MODELS[model]) {
      return c.json({ error: `Unknown model: ${model}. Available: ${Object.keys(MODELS).join(', ')}` }, 400)
    }

    const probability = predict(model, features)
    const riskLevel = probability < 0.25 ? 'low' : probability < 0.55 ? 'moderate' : 'high'

    // Save to D1 if available
    try {
      const db = c.env.DB
      if (db) {
        await db.prepare(
          `INSERT INTO predictions (model, features, probability, risk_level, created_at) VALUES (?, ?, ?, ?, ?)`
        ).bind(model, JSON.stringify(features), probability, riskLevel, new Date().toISOString()).run()
      }
    } catch (e) {
      // DB not available or table not created yet - continue without saving
    }

    return c.json({
      model,
      probability: Math.round(probability * 10000) / 10000,
      risk_level: riskLevel,
      confidence: MODELS[model].auc,
      timestamp: new Date().toISOString()
    })
  } catch (e: any) {
    return c.json({ error: e.message || 'Prediction failed' }, 500)
  }
})

// Batch prediction (all 5 diseases at once)
app.post('/api/predict/batch', async (c) => {
  try {
    const body = await c.req.json()
    const { features } = body

    if (!features) {
      return c.json({ error: 'features object is required' }, 400)
    }

    const results: Record<string, { probability: number; risk_level: string; confidence: number }> = {}

    for (const modelName of Object.keys(MODELS)) {
      const probability = predict(modelName, features)
      results[modelName] = {
        probability: Math.round(probability * 10000) / 10000,
        risk_level: probability < 0.25 ? 'low' : probability < 0.55 ? 'moderate' : 'high',
        confidence: MODELS[modelName].auc
      }
    }

    return c.json({ results, timestamp: new Date().toISOString() })
  } catch (e: any) {
    return c.json({ error: e.message || 'Batch prediction failed' }, 500)
  }
})

// 집계 통계만 공개한다.
// 이전 버전은 인증 없이 `SELECT *` 로 모든 입력 피처(BMI·수면·흡연·음주 등 건강정보)를
// 전량 반환하고 있었다. 개별 레코드는 더 이상 외부로 내보내지 않는다.
app.get('/api/predictions', async (c) => {
  try {
    const db = c.env.DB
    if (!db) return c.json({ stats: [], message: 'DB not configured' })

    const { results } = await db.prepare(
      `SELECT model, risk_level, COUNT(*) AS count, ROUND(AVG(probability), 4) AS avg_probability
       FROM predictions GROUP BY model, risk_level ORDER BY model, risk_level`
    ).all()
    const total: any = await db.prepare('SELECT COUNT(*) AS total FROM predictions').first()

    return c.json({ stats: results, total: total?.total || 0 })
  } catch (e: any) {
    return c.json({ stats: [], error: e.message })
  }
})

// Model info
app.get('/api/models', (c) => {
  const info = Object.entries(MODELS).map(([name, m]) => ({
    name,
    auc: m.auc,
    features: Object.keys(m.coeffs),
    feature_count: Object.keys(m.coeffs).length
  }))
  return c.json({ models: info })
})

// ══════════════════════════════════════════
// STATIC FILES (HTML pages)
// ══════════════════════════════════════════

// Root route - serve index.html directly to avoid redirect loop
// Cloudflare Pages 308 redirects /index.html → / so we must handle / in worker
app.get('/', async (c) => {
  // Return the asset from the static files
  return c.env.ASSETS.fetch(new Request(new URL('/index.html', c.req.url)))
})

export default app
