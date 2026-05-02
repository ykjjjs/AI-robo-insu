import { Hono } from 'hono'
import { cors } from 'hono/cors'

type Bindings = {
  DB: D1Database
  ASSETS: Fetcher
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

async function hashSHA256(text: string): Promise<string> {
  const enc = new TextEncoder().encode(text)
  const buf = await crypto.subtle.digest('SHA-256', enc)
  return [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2, '0')).join('')
}

async function hashPin(pin: string, salt: string): Promise<string> {
  return hashSHA256(pin + ':' + salt)
}

function makeToken(userId: number, username: string): string {
  const payload = JSON.stringify({ uid: userId, u: username, t: Date.now() })
  // Base64-encode for simple token (no jwt lib needed in Workers)
  return btoa(payload)
}

function parseToken(token: string): { uid: number; u: string; t: number } | null {
  try {
    return JSON.parse(atob(token))
  } catch { return null }
}

// ══════════════════════════════════════════
// AUTH API ROUTES
// ══════════════════════════════════════════

// Sign Up — 주민번호(SHA256 암호화), 이름, 모바일, 아이디, 비번 4자리
app.post('/api/auth/signup', async (c) => {
  try {
    const db = c.env.DB
    const { username, pin, name, mobile, ssn } = await c.req.json()

    if (!username || !pin || !name || !mobile || !ssn) {
      return c.json({ error: '모든 필드를 입력해주세요.' }, 400)
    }
    if (!/^\d{4}$/.test(pin)) {
      return c.json({ error: '비밀번호는 숫자 4자리여야 합니다.' }, 400)
    }
    if (!/^\d{6}-?\d{7}$/.test(ssn.replace(/\s/g, ''))) {
      return c.json({ error: '주민등록번호 형식이 올바르지 않습니다.' }, 400)
    }
    if (username.length < 2 || username.length > 20) {
      return c.json({ error: '아이디는 2~20자여야 합니다.' }, 400)
    }

    // Check duplicate username
    const existing = await db.prepare('SELECT id FROM users WHERE username = ?').bind(username).first()
    if (existing) {
      return c.json({ error: '이미 사용 중인 아이디입니다.' }, 409)
    }

    const ssnClean = ssn.replace(/[-\s]/g, '')
    const ssnHash = await hashSHA256(ssnClean)
    const pinHash = await hashPin(pin, username)
    const now = new Date().toISOString()

    const result = await db.prepare(
      'INSERT INTO users (username, pin, name, mobile, ssn_hash, created_at) VALUES (?, ?, ?, ?, ?, ?)'
    ).bind(username, pinHash, name, mobile, ssnHash, now).run()

    const userId = result.meta.last_row_id as number
    const token = makeToken(userId, username)

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

    const user: any = await db.prepare('SELECT * FROM users WHERE username = ?').bind(username).first()
    if (!user) {
      return c.json({ error: '아이디 또는 비밀번호가 일치하지 않습니다.' }, 401)
    }

    const pinHash = await hashPin(pin, username)
    if (pinHash !== user.pin) {
      return c.json({ error: '아이디 또는 비밀번호가 일치하지 않습니다.' }, 401)
    }

    const token = makeToken(user.id, user.username)
    return c.json({ ok: true, token, user: { id: user.id, username: user.username, name: user.name } })
  } catch (e: any) {
    return c.json({ error: e.message || '로그인 실패' }, 500)
  }
})

// Get current user info (token verification)
app.get('/api/auth/me', async (c) => {
  try {
    const auth = c.req.header('Authorization')
    if (!auth || !auth.startsWith('Bearer ')) {
      return c.json({ error: '인증이 필요합니다.' }, 401)
    }
    const parsed = parseToken(auth.slice(7))
    if (!parsed) {
      return c.json({ error: '유효하지 않은 토큰입니다.' }, 401)
    }

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
    const auth = c.req.header('Authorization')
    if (!auth || !auth.startsWith('Bearer ')) {
      return c.json({ error: '로그인이 필요합니다.' }, 401)
    }
    const parsed = parseToken(auth.slice(7))
    if (!parsed) return c.json({ error: '유효하지 않은 토큰' }, 401)

    const db = c.env.DB
    const { stage, result_data } = await c.req.json()
    if (!stage || !result_data) {
      return c.json({ error: 'stage와 result_data가 필요합니다.' }, 400)
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
    const auth = c.req.header('Authorization')
    if (!auth || !auth.startsWith('Bearer ')) {
      return c.json({ error: '로그인이 필요합니다.' }, 401)
    }
    const parsed = parseToken(auth.slice(7))
    if (!parsed) return c.json({ error: '유효하지 않은 토큰' }, 401)

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
    const auth = c.req.header('Authorization')
    if (!auth || !auth.startsWith('Bearer ')) {
      return c.json({ error: '로그인이 필요합니다.' }, 401)
    }
    const parsed = parseToken(auth.slice(7))
    if (!parsed) return c.json({ error: '유효하지 않은 토큰' }, 401)

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

// Get prediction history
app.get('/api/predictions', async (c) => {
  try {
    const db = c.env.DB
    if (!db) return c.json({ predictions: [], message: 'DB not configured' })

    const { results } = await db.prepare(
      `SELECT * FROM predictions ORDER BY created_at DESC LIMIT 50`
    ).all()

    return c.json({ predictions: results })
  } catch (e: any) {
    return c.json({ predictions: [], error: e.message })
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
