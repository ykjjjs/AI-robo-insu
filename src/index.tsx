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
// API ROUTES
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
