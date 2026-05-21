import fetch   from 'node-fetch';
// ============================================================
//  ARKA Intelligence Center — Relay Server v18
//  Rewrite limpio — Mar 2026 | Security hardening — May 2026
//  v18: Rate limiter removido — seguridad via relay-secret + Origin check
// ============================================================
import express from 'express';
import cors    from 'cors';

const app    = express();
const SECRET = process.env.RELAY_SHARED_SECRET || '';
const PORT   = process.env.PORT || 3001;

// ── Middlewares ───────────────────────────────────────────────
app.use(cors({
  origin: [
    /^https?:\/\/localhost(:\d+)?$/,
    /^https:\/\/.*\.vercel\.app$/,
    /^https:\/\/.*\.up\.railway\.app$/,
    /^https:\/\/arka-intelligence\.vercel\.app$/,
    /^https:\/\/.*\.arkaltd\.io$/,
    /^https:\/\/world\.arkaltd\.io$/,
  ],
  methods: ['GET','POST','OPTIONS'],
  allowedHeaders: ['Content-Type','x-relay-key','Authorization'],
}));
app.options('*', cors());
app.use(express.json());

// ── Allowed origins (Origin/Referer check) ────────────────────
const ALLOWED_ORIGINS = [
  /^https?:\/\/localhost(:\d+)?$/,
  /^https:\/\/arka-intelligence\.vercel\.app$/,
  /^https:\/\/arka-intelligence-[a-z0-9-]+\.vercel\.app$/,
  /^https:\/\/[a-z0-9-]+\.arkaltd\.io$/,
];
function originAllowed(req) {
  const o = req.headers['origin'] || req.headers['referer'] || '';
  if (!o) return false; // sin origen → rechazar (no es browser)
  try {
    const base = new URL(o).origin; // normaliza — quita path del referer
    return ALLOWED_ORIGINS.some(re => re.test(base));
  } catch { return false; }
}

// ── Auth middleware ───────────────────────────────────────────
function auth(req, res, next) {
  // 1. Verifica relay secret
  if (SECRET) {
    const k = req.headers['x-relay-key'] || (req.headers.authorization||'').replace('Bearer ','');
    if (k !== SECRET) return res.status(401).json({ error:'Unauthorized' });
  }
  // 2. Verifica Origin/Referer — bloquea uso desde dominios no autorizados
  //    aunque alguien extraiga el secret del bundle JS no puede usarlo fuera de los dominios ARKA
  if (!originAllowed(req)) {
    return res.status(403).json({ error:'Forbidden origin' });
  }
  next();
}

// ── Rate limiter: REMOVIDO en v18 ────────────────────────────
// La seguridad viene exclusivamente de relay-secret + Origin check.
// El rate limiter estaba bloqueando tráfico legítimo del propio app
// (múltiples paneles React montando simultáneamente = >2000 req/min
// desde la misma IP de Vercel). No hay necesidad de limitarlo aquí.

// ── In-memory cache ───────────────────────────────────────────
const cache = new Map();
function getCached(k) {
  const e = cache.get(k);
  if (!e) return null;
  if (Date.now() > e.exp) { cache.delete(k); return null; }
  return e.data;
}
function setCached(k, data, ttlMs = 300_000) {
  cache.set(k, { data, exp: Date.now() + ttlMs });
}

// ── fetchJSON helper ──────────────────────────────────────────
async function fetchJSON(url, opts = {}, timeout = 15000, retries = 2) {
  for (let attempt = 0; attempt <= retries; attempt++) {
    const ctrl = new AbortController();
    const t = setTimeout(() => ctrl.abort(), timeout);
    try {
      const r = await fetch(url, {
        headers: { 'User-Agent':'ARKARelay/7.0', Accept:'application/json', ...(opts.headers||{}) },
        signal: ctrl.signal,
      });
      clearTimeout(t);
      if (r.status === 429) {
        if (attempt < retries) { await new Promise(r => setTimeout(r, 3000 * (attempt + 1))); continue; }
        throw new Error('HTTP 429');
      }
      if (!r.ok) throw new Error(`HTTP ${r.status}`);
      return await r.json();
    } catch(e) {
      clearTimeout(t);
      if (attempt < retries && !e.message.includes('429')) { await new Promise(r => setTimeout(r, 1000)); continue; }
      throw e;
    }
  }
}

// ── /health ───────────────────────────────────────────────────
app.get('/health', (_req, res) => {
  res.json({ status:'ok', version:18, ts: new Date().toISOString(),
    endpoints:['/health','/market-snapshot','/finnhub','/fred','/nyt','/guardian',
               '/newsapi','/gdelt','/polymarket','/opensky','/ais',
               '/rss','/oref','/ai','/cyber-feed','/military-feed','/pizzint','/fx','/firms','/cloudflare'] });
});

// ── /market-snapshot ─────────────────────────────────────────
app.get('/market-snapshot', auth, async (req, res) => {
  const ck = 'market_snap';
  const cached = getCached(ck);
  if (cached) return res.json(cached);
  try {
    await new Promise(r => setTimeout(r, 1500));
    const key = process.env.FINNHUB_API_KEY;
    // Stocks & ETFs (Finnhub /quote)
    const stockSyms = [
      'AAPL','MSFT','GOOGL','AMZN','TSLA','NVDA','META','TSM',
      'SPY','QQQ','GLD','TLT','XLF','USO','UNG','SLV','DBB',
    ];
    // Crypto via Binance on Finnhub
    const cryptoSyms = [
      'BINANCE:BTCUSDT','BINANCE:ETHUSDT','BINANCE:SOLUSDT',
      'BINANCE:BNBUSDT','BINANCE:XRPUSDT','BINANCE:USDCUSDT',
    ];
    const syms = [...stockSyms, ...cryptoSyms];
    const [stockResults, fxData] = await Promise.all([
      Promise.allSettled(
        syms.map(s => fetchJSON(`https://finnhub.io/api/v1/quote?symbol=${s}&token=${key}`).then(d=>({s,d})))
      ),
      Promise.all([
        fetchJSON('https://api.frankfurter.app/latest?from=EUR&to=USD,GBP,JPY,MXN,CAD,CHF,BRL,AUD,CNY'),
        fetchJSON('https://api.frankfurter.app/latest?from=USD&to=MXN,BRL,JPY,EUR,GBP,CAD,CHF,ARS,CLP'),
      ]).catch(() => [null, null]),
    ]);
    const data = {};
    for (const r of stockResults) {
      if (r.status==='fulfilled') data[r.value.s] = r.value.d;
    }
    // Inyectar pares FX desde Frankfurter en formato compatible con fromQuote
    const [eurRates, usdRates] = fxData;
    const fxPairs = {
      'FX:EUR_USD': { base: 'EUR', quote: 'USD', rate: eurRates?.rates?.USD },
      'FX:EUR_MXN': { base: 'EUR', quote: 'MXN', rate: eurRates?.rates?.MXN },
      'FX:EUR_GBP': { base: 'EUR', quote: 'GBP', rate: eurRates?.rates?.GBP },
      'FX:EUR_JPY': { base: 'EUR', quote: 'JPY', rate: eurRates?.rates?.JPY },
      'FX:EUR_BRL': { base: 'EUR', quote: 'BRL', rate: eurRates?.rates?.BRL },
      'FX:USD_MXN': { base: 'USD', quote: 'MXN', rate: usdRates?.rates?.MXN },
      'FX:USD_BRL': { base: 'USD', quote: 'BRL', rate: usdRates?.rates?.BRL },
      'FX:USD_JPY': { base: 'USD', quote: 'JPY', rate: usdRates?.rates?.JPY },
      'FX:USD_CAD': { base: 'USD', quote: 'CAD', rate: usdRates?.rates?.CAD },
      'FX:USD_CHF': { base: 'USD', quote: 'CHF', rate: usdRates?.rates?.CHF },
      'FX:GBP_USD': { base: 'GBP', quote: 'USD', rate: eurRates?.rates?.USD && eurRates?.rates?.GBP ? (eurRates.rates.USD / eurRates.rates.GBP) : null },
    };
    for (const [sym, fx] of Object.entries(fxPairs)) {
      if (fx.rate) data[sym] = { c: fx.rate, dp: 0, h: fx.rate, l: fx.rate, o: fx.rate };
    }
    setCached(ck, data, 180_000);
    res.json(data);
  } catch(e){ res.status(502).json({error:e.message}); }
});

// ── /finnhub ─────────────────────────────────────────────────
app.get('/finnhub', auth, async (req, res) => {
  const key = process.env.FINNHUB_API_KEY;
  const { path: p='quote', ...rest } = req.query;
  const ck = `finnhub_${p}_${JSON.stringify(rest)}`;
  const cached = getCached(ck);
  if (cached) return res.json(cached);
  const params = new URLSearchParams({...rest, token:key});
  try {
    const data = await fetchJSON(`https://finnhub.io/api/v1/${p}?${params}`);
    setCached(ck, data, 60_000); // 60s cache — alinea con TTL de markets en frontend
    res.json(data);
  } catch(e){ res.status(502).json({error:e.message}); }
});

// ── /alphavantage ────────────────────────────────────────────
app.get('/alphavantage', auth, async (req, res) => {
  const key = process.env.ALPHA_VANTAGE_KEY;
  const ck = `av_${JSON.stringify(req.query)}`;
  const cached = getCached(ck);
  if (cached) return res.json(cached);
  try {
    const params = new URLSearchParams({...req.query, apikey:key});
    const data = await fetchJSON(`https://www.alphavantage.co/query?${params}`);
    setCached(ck, data, 240_000); // 4 min cache (respeta rate limits del free plan)
    res.json(data);
  } catch(e){ res.status(502).json({error:e.message}); }
});

// ── /fred ─────────────────────────────────────────────────────
app.get('/fred', auth, async (req, res) => {
  const key = process.env.FRED_API_KEY;
  const ck = `fred_${JSON.stringify(req.query)}`;
  const cached = getCached(ck);
  if (cached) return res.json(cached);
  try {
    const params = new URLSearchParams({...req.query, api_key:key, file_type:'json'});
    const data = await fetchJSON(`https://api.stlouisfed.org/fred/series/observations?${params}`);
    setCached(ck, data, 3600_000);
    res.json(data);
  } catch(e){ res.status(502).json({error:e.message}); }
});

// ── /nyt ─────────────────────────────────────────────────────
app.get('/nyt', auth, async (req, res) => {
  const key = process.env.NYT_API_KEY;
  if (!key) return res.status(503).json({ error: 'NYT_API_KEY not configured' });
  const { section, type, ...rest } = req.query;
  const ck = `nyt_${section||'world'}_${type||'top'}`;
  const cached = getCached(ck);
  if (cached) return res.json(cached);
  try {
    let url;
    if (type === 'search') {
      const params = new URLSearchParams({ ...rest, 'api-key': key });
      url = `https://api.nytimes.com/svc/search/v2/articlesearch.json?${params}`;
    } else {
      // top stories (default)
      url = `https://api.nytimes.com/svc/topstories/v2/${section || 'world'}.json?api-key=${key}`;
    }
    const data = await fetchJSON(url);
    setCached(ck, data, 900_000);
    res.json(data);
  } catch(e){ res.status(502).json({error:e.message}); }
});

// ── /guardian ─────────────────────────────────────────────────
app.get('/guardian', auth, async (req, res) => {
  const key = process.env.GUARDIAN_API_KEY;
  if (!key) return res.status(503).json({ error: 'GUARDIAN_API_KEY not configured' });
  const ck = `guardian_${JSON.stringify(req.query)}`;
  const cached = getCached(ck);
  if (cached) return res.json(cached);
  try {
    const params = new URLSearchParams({ ...req.query, 'api-key': key });
    const data = await fetchJSON(`https://content.guardianapis.com/search?${params}`);
    setCached(ck, data, 900_000);
    res.json(data);
  } catch(e){ res.status(502).json({error:e.message}); }
});

// ── /newsapi ─────────────────────────────────────────────────
app.get('/newsapi', auth, async (req, res) => {
  const key = process.env.NEWSAPI_KEY;
  const ck = `newsapi_${JSON.stringify(req.query)}`;
  const cached = getCached(ck);
  if (cached) return res.json(cached);
  try {
    const params = new URLSearchParams(req.query);
    const data = await fetchJSON(`https://newsapi.org/v2/everything?${params}`,
      { headers:{'X-Api-Key':key} });
    setCached(ck, data, 600_000);
    res.json(data);
  } catch(e){ res.status(502).json({error:e.message}); }
});

// ── /gdelt ───────────────────────────────────────────────────
app.get('/gdelt', auth, async (req, res) => {
  const ck = `gdelt_${JSON.stringify(req.query)}`;
  const cached = getCached(ck);
  if (cached) return res.json(cached);
  try {
    const params = new URLSearchParams({...req.query, format:'json'});
    const data = await fetchJSON(`https://api.gdeltproject.org/api/v2/doc/doc?${params}`);
    setCached(ck, data, 1_800_000);
    res.json(data);
  } catch(e){ res.status(502).json({error:e.message}); }
});



// ── /fx ───────────────────────────────────────────────────────
app.get('/fx', auth, async (req, res) => {
  const ck = 'fx_rates';
  const cached = getCached(ck);
  if (cached) return res.json(cached);
  try {
    const [eurBase, usdBase] = await Promise.all([
      fetchJSON('https://api.frankfurter.app/latest?from=EUR&to=USD,GBP,JPY,MXN,CAD,CHF,BRL,AUD,CNY'),
      fetchJSON('https://api.frankfurter.app/latest?from=USD&to=MXN,BRL,JPY,EUR,GBP,CAD,CHF,ARS,CLP'),
    ]);
    const data = { eur: eurBase, usd: usdBase, ts: Date.now() };
    setCached(ck, data, 300_000); // caché 5 min
    res.json(data);
  } catch(e){ res.status(502).json({error:e.message}); }
});


// ── /pizzint ──────────────────────────────────────────────────
app.get('/pizzint', auth, async (req, res) => {
  const ck = 'pizzint_data_v2';
  const cached = getCached(ck);
  if (cached) return res.json(cached);
  try {
    const r = await fetch('https://www.pizzint.watch/', {
      headers: {
        'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.5',
      },
      signal: AbortSignal.timeout(20000),
    });
    const html = await r.text();
    let doomsday = null, commute = null;
    try {
      const DOOM_KEY = '\\"initialDoomsdayData\\":';
      const COMM_KEY = '\\"initialCommuteData\\":';
      const d1 = html.indexOf(DOOM_KEY);
      const d2 = html.indexOf(',\\"initialCommuteData\\"');
      const c1 = html.indexOf(COMM_KEY);
      const c2 = html.indexOf(',\\"championMarketUrl\\"');
      if (d1 > 0 && d2 > 0) {
        const raw = html.slice(d1 + DOOM_KEY.length, d2);
        doomsday = JSON.parse(raw.replace(/\\\\"/g, '"'));
      }
      if (c1 > 0 && c2 > 0) {
        const raw = html.slice(c1 + COMM_KEY.length, c2);
        commute = JSON.parse(raw.replace(/\\\\"/g, '"'));
      }
    } catch(parseErr) { console.error('pizzint parse error:', parseErr.message); }
    console.log('pizzint debug - d1:', html.indexOf('\\"initialDoomsdayData\\":'), 'html_len:', html.length);
        const data = { doomsday, commute, ts: Date.now() };
    setCached(ck, data, 300_000); // caché 5 min
    res.json(data);
  } catch(e) { res.status(502).json({ error: e.message }); }
});

// ── /firms ───────────────────────────────────────────────────
app.get('/firms', auth, async (req, res) => {
  const NASA_KEY = process.env.NASA_FIRMS_KEY || '98e3b5113209d4813a6e82eda1dc0bea';
  const ck = 'firms_fires';
  const cached = getCached(ck);
  if (cached) return res.json(cached);
  try {
    const url = `https://firms.modaps.eosdis.nasa.gov/api/area/csv/${NASA_KEY}/VIIRS_SNPP_NRT/world/1`;
    const resp = await fetch(url, { signal: AbortSignal.timeout(20000) });
    const text = await resp.text();
    setCache(ck, { csv: text }, 10 * 60 * 1000); // caché 10 min
    res.json({ csv: text });
  } catch (e) {
    res.status(502).json({ error: e.message });
  }
});

// ── /cloudflare — Cloudflare Radar Internet Outages ──────────
app.get('/cloudflare', auth, async (req, res) => {
  const CF_KEY = process.env.CLOUDFLARE_API_TOKEN;
  if (!CF_KEY) return res.status(503).json({ error: 'CLOUDFLARE_API_TOKEN not configured' });
  const ck = 'cf_radar_netflows';
  const cached = getCached(ck);
  if (cached) return res.json(cached);
  try {
    const r = await fetch(
      'https://api.cloudflare.com/client/v4/radar/netflows/timeseries?aggInterval=1h&dateRange=24h',
      { headers: { Authorization: `Bearer ${CF_KEY}`, 'Content-Type': 'application/json' } }
    );
    if (!r.ok) throw new Error(`Cloudflare ${r.status}`);
    const data = await r.json();
    setCached(ck, data, 5 * 60 * 1000); // caché 5 min
    res.json(data);
  } catch (e) {
    res.status(502).json({ error: e.message });
  }
});

// ── /economic-calendar ────────────────────────────────────────
// Mapa release_id → series_id para los releases más importantes
const RELEASE_SERIES = {
  10:  { s:'CPIAUCSL',  unit:'%YoY',  label:'CPI'           },
  46:  { s:'UNRATE',    unit:'%',     label:'Unemployment'   },
  50:  { s:'PAYEMS',    unit:'K',     label:'Nonfarm Payroll'},
  53:  { s:'GDP',       unit:'%',     label:'GDP'            },
  55:  { s:'FEDFUNDS',  unit:'%',     label:'Fed Funds'      },
  56:  { s:'PCEPILFE',  unit:'%YoY',  label:'Core PCE'       },
  57:  { s:'RSAFS',     unit:'%MoM',  label:'Retail Sales'   },
  82:  { s:'INDPRO',    unit:'%',     label:'Ind. Production'},
  86:  { s:'CPILFESL',  unit:'%YoY',  label:'Core CPI'       },
  175: { s:'ISMPMI',    unit:'',      label:'ISM Mfg PMI'    },
  196: { s:'HOUST',     unit:'K',     label:'Housing Starts' },
  236: { s:'PPIFGS',    unit:'%YoY',  label:'PPI'            },
};

const RELEASE_BY_NAME = {
  'Consumer Price Index':   { s:'CPIAUCSL',   unit:'idx',  label:'CPI'           },
  'Employment Situation':   { s:'UNRATE',     unit:'%',    label:'Unemployment'  },
  'Nonfarm':                { s:'PAYEMS',     unit:'K',    label:'Nonfarm Payroll'},
  'Gross Domestic Product': { s:'GDP',        unit:'B$',   label:'GDP'           },
  'Personal Consumption':   { s:'PCEPILFE',   unit:'idx',  label:'Core PCE'      },
  'Retail Sales':           { s:'RSAFS',      unit:'M$',   label:'Retail Sales'  },
  'Industrial Production':  { s:'INDPRO',     unit:'idx',  label:'Ind. Production'},
  'Commercial Paper':       { s:'CP',         unit:'B$',   label:'Comm. Paper'   },
  'Federal Funds':          { s:'FEDFUNDS',   unit:'%',    label:'Fed Funds'     },
  'FOMC':                   { s:'FEDFUNDS',   unit:'%',    label:'Fed Funds Rate'},
  'Empire State':           { s:'GAUTHMPMI',  unit:'',     label:'Empire State'  },
  'Housing Starts':         { s:'HOUST',      unit:'K',    label:'Housing Starts'},
  'Producer Price':         { s:'PPIACO',     unit:'idx',  label:'PPI'           },
  'Trade Balance':          { s:'BOPGSTB',    unit:'M$',   label:'Trade Balance' },
  'Durable Goods':          { s:'DGORDER',    unit:'M$',   label:'Durable Goods' },
  'G.17':                   { s:'INDPRO',     unit:'idx',  label:'Ind. Production'},
};

app.get('/economic-calendar', auth, async (req, res) => {
  const ck = 'econ_calendar_v7';
  const cached = getCached(ck);
  if (cached) return res.json(cached);
  try {
    const key = process.env.FRED_API_KEY;
    const today = new Date();
    const todayStr = today.toISOString().slice(0,10);
    // Ventana: últimos 7 días + próximos 21 días
    const from = new Date(today.getTime() - 7*24*60*60*1000).toISOString().slice(0,10);
    const to   = new Date(today.getTime() + 21*24*60*60*1000).toISOString().slice(0,10);

    // FRED releases/dates con realtime_start muy antiguo para capturar todo
    // lo histórico y scheduled. Bajamos 500 registros ordenados desc (más recientes
    // primero) y luego filtramos por la ventana de fechas deseada.
    const params = new URLSearchParams({
      api_key: key, file_type: 'json',
      realtime_start: '2020-01-01',
      limit: '500', sort_order: 'desc', order_by: 'release_date',
    });
    const data = await fetchJSON(`https://api.stlouisfed.org/fred/releases/dates?${params}`, {}, 30000);

    const HIGH = ['GDP','CPI','Employment','Nonfarm','Federal Funds','PCE','Retail Sales','PPI','Housing Starts','ISM'];
    const MED  = ['PMI','Trade','Industrial','Consumer','Producer','Durable','Treasury','Manufacturing'];

    const events = (data.release_dates || [])
      .filter(r => r.date >= from && r.date <= to)
      .map(r => {
        const imp = HIGH.some(k => r.release_name.includes(k)) ? 3 :
                    MED.some(k => r.release_name.includes(k)) ? 2 : 1;
        const released = r.date <= todayStr;
        return { date: r.date, name: r.release_name, importance: imp, id: r.release_id, released };
      }).sort((a,b) => new Date(a.date) - new Date(b.date));

    // Enriquecer eventos con valor actual + histórico para los releases mapeados
    const enriched = await Promise.allSettled(
      events.map(async e => {
        // Try ID-based lookup first, then name-based
        let mapping = RELEASE_SERIES[e.id];
        if (!mapping) {
          const nameKey = Object.keys(RELEASE_BY_NAME).find(k => e.name.includes(k));
          mapping = nameKey ? RELEASE_BY_NAME[nameKey] : null;
        }
        if (!mapping) return e;
        try {
          const obsParams = new URLSearchParams({
            series_id: mapping.s, api_key: key, file_type: 'json',
            limit: '13', sort_order: 'desc'
          });
          const obs = await fetchJSON(`https://api.stlouisfed.org/fred/series/observations?${obsParams}`, {}, 15000);
          const validObs = (obs.observations || []).filter(o => o.value !== '.');
          const latest = validObs[0];
          const prev   = validObs[1];
          const history = validObs.slice(0,12).reverse().map(o => ({
            date: o.date, value: parseFloat(o.value)
          }));
          return {
            ...e,
            actual:   latest ? parseFloat(latest.value) : null,
            previous: prev   ? parseFloat(prev.value)   : null,
            unit:     mapping.unit,
            seriesLabel: mapping.label,
            history,
          };
        } catch { return e; }
      })
    );

    const finalEvents = enriched.map(r => r.status === 'fulfilled' ? r.value : r.reason);
    setCached(ck, { events: finalEvents, from, to, ts: Date.now() }, 3600_000);
    res.json({ events: finalEvents, from, to, ts: Date.now() });
  } catch(e) { res.status(502).json({ error: e.message }); }
});

// ── /tension — Global Tension Index from Polymarket ──────────
app.get('/tension', auth, async (req, res) => {
  const ck = 'tension_index_v3';
  const cached = getCached(ck);
  if (cached) return res.json(cached);
  try {
    // Buscar markets de conflicto militar/geopolítico
    const INCLUDE = ['invade','invasion','nuclear','missile','military','war','strike',
      'attack','nato','conflict','clash','troops','annex','seize','blockade',
      'coup','regime','civil war','ground operation','capture','sanctions'];
    const EXCLUDE = ['nba','nfl','nhl','mlb','stanley cup','super bowl','world series',
      'nomination','presidential','congress','senate','governor','mayor',
      'oscar','grammy','bitcoin','crypto','gta','video game','season','award',
      'championship','finals','league','tournament','win the','openai','apple',
      'google','microsoft','tesla','musk','trump win','election'];
    const params = new URLSearchParams({ limit: '300', active: 'true', closed: 'false' });
    const markets = await fetchJSON(`https://gamma-api.polymarket.com/markets?${params}`);
    
    // Filtrar mercados relevantes
    const conflictMarkets = markets.filter(m => {
      const q = (m.question || '').toLowerCase();
      const hasInclude = INCLUDE.some(k => q.includes(k));
      const hasExclude = EXCLUDE.some(k => q.includes(k));
      return hasInclude && !hasExclude;
    }).map(m => {
      const prices = JSON.parse(m.outcomePrices || '[0,0]');
      const price = parseFloat(prices[0]) || parseFloat(m.lastTradePrice) || 0;
      return {
        question: m.question,
        slug: m.slug,
        probability: Math.round(price * 100),
        volume: Math.round(m.volumeNum || 0),
        change24h: m.oneDayPriceChange || 0,
      };
    }).filter(m => m.probability > 0 && m.volume > 5000)
      .sort((a, b) => b.volume - a.volume)
      .slice(0, 20);

    // Calcular tension index (0-100)
    const weightedSum = conflictMarkets.reduce((sum, m) => sum + (m.probability * Math.log10(m.volume + 1)), 0);
    const weightTotal = conflictMarkets.reduce((sum, m) => sum + Math.log10(m.volume + 1), 0);
    const tensionScore = weightTotal > 0 ? Math.round(weightedSum / weightTotal) : 0;
    
    // Clasificar nivel
    const defconLevel = tensionScore > 40 ? 2 : tensionScore > 25 ? 3 : tensionScore > 15 ? 4 : 5;
    const label = tensionScore > 40 ? 'CRITICAL' : tensionScore > 25 ? 'ELEVATED' : tensionScore > 15 ? 'GUARDED' : 'NORMAL';

    const data = { tensionScore, defconLevel, label, markets: conflictMarkets, ts: Date.now() };
    setCached(ck, data, 600_000); // caché 10 min
    res.json(data);
  } catch(e) { res.status(502).json({ error: e.message }); }
});

// ── /polymarket ───────────────────────────────────────────────
app.get('/polymarket', auth, async (req, res) => {
  const ck = `poly_${JSON.stringify(req.query)}`;
  const cached = getCached(ck);
  if (cached) return res.json(cached);
  try {
    const params = new URLSearchParams(req.query);
    const data = await fetchJSON(`https://gamma-api.polymarket.com/markets?${params}`);
    setCached(ck, data, 600_000);
    res.json(data);
  } catch(e){ res.status(502).json({error:e.message}); }
});

// ── /opensky ─────────────────────────────────────────────────
// OpenSky free: ~6000 states con OAuth2, ~400 sin auth
// Estrategia: intentar OAuth2 primero, fallback a anon, cache 2min
let _osToken = null;
let _osTokenExp = 0;

async function getOSToken() {
  if (_osToken && Date.now() < _osTokenExp - 30000) return _osToken;
  const id = process.env.OPENSKY_CLIENT_ID;
  const sec = process.env.OPENSKY_CLIENT_SECRET;
  if (!id || !sec) return null;
  try {
    const r = await fetch('https://auth.opensky-network.org/auth/realms/opensky-network/protocol/openid-connect/token', {
      method:'POST',
      headers:{'Content-Type':'application/x-www-form-urlencoded'},
      body:new URLSearchParams({ grant_type:'client_credentials', client_id:id, client_secret:sec }),
      signal: AbortSignal.timeout(8000),
    });
    if (!r.ok) return null;
    const { access_token, expires_in } = await r.json();
    _osToken = access_token;
    _osTokenExp = Date.now() + (expires_in * 1000);
    return access_token;
  } catch { return null; }
}

app.get('/opensky', auth, async (req, res) => {
  const ck = 'opensky_global';
  const cached = getCached(ck);
  if (cached) return res.json(cached);

  const { lamin='-60', lamax='75', lomin='-180', lomax='180' } = req.query;
  const url = `https://opensky-network.org/api/states/all?lamin=${lamin}&lamax=${lamax}&lomin=${lomin}&lomax=${lomax}`;

  // Intento 1: con OAuth2 (más estados, menos rate-limit)
  const token = await getOSToken();
  if (token) {
    try {
      const data = await fetchJSON(url, { headers:{ Authorization:`Bearer ${token}` } }, 25000, 1);
      if (data?.states?.length) {
        setCached(ck, data, 120_000);
        return res.json(data);
      }
    } catch(e) {
      if (e.message.includes('401') || e.message.includes('403')) { _osToken = null; } // invalidar token
    }
  }

  // Intento 2: anónimo (sin auth — devuelve ~400 estados pero siempre funciona)
  try {
    const data = await fetchJSON(url, {}, 20000, 1);
    setCached(ck, data, 120_000);
    return res.json(data);
  } catch(e) {
    return res.status(503).json({ error:`OpenSky unavailable: ${e.message}`, states:[] });
  }
});

// ── /ais ─────────────────────────────────────────────────────
app.get('/ais', auth, async (req, res) => {
  const ck = 'ais_global';
  const cached = getCached(ck);
  if (cached) return res.json(cached);
  try {
    const apiKey = process.env.AISSTREAM_API_KEY;
    // AISStream REST snapshot — últimos 200 vessels activos
    const data = await fetchJSON(
      `https://api.aisstream.io/v0/vessel/location?apiKey=${apiKey}&limit=200`
    );
    setCached(ck, data, 120_000);
    res.json(data);
  } catch(e){ res.status(502).json({error:e.message}); }
});

// ── /rss ─────────────────────────────────────────────────────
app.get('/rss', auth, async (req, res) => {
  const { url } = req.query;
  if (!url) return res.status(400).json({error:'url required'});
  const ck = `rss_${url}`;
  const cached = getCached(ck);
  if (cached) return res.json(cached);
  try {
    const r = await fetch(url, { headers:{'User-Agent':'ARKARelay/7.0','Accept':'application/rss+xml,application/xml,text/xml,*/*'} });
    if (!r.ok) throw new Error(`HTTP ${r.status}`);
    const text = await r.text();
    setCached(ck, { xml: text }, 900_000);
    res.json({ xml: text });
  } catch(e){ res.status(502).json({error:e.message}); }
});

// ── /oref ─────────────────────────────────────────────────────
app.get('/oref', auth, async (req, res) => {
  try {
    const data = await fetchJSON('https://www.oref.org.il/WarningMessages/History/AlertsHistory.json',
      { headers:{ Referer:'https://www.oref.org.il/' } });
    res.json(data);
  } catch(e){ res.status(502).json({error:e.message}); }
});

// ── /cyber-feed ───────────────────────────────────────────────
app.get('/cyber-feed', auth, async (req, res) => {
  const ck = 'cyber_feed';
  const cached = getCached(ck);
  if (cached) return res.json(cached);
  try {
    const params = new URLSearchParams({
      query:'ransomware cyberattack "zero-day" APT malware "data breach" hacking intrusion',
      mode:'artlist', maxrecords:'15', timespan:'24h', sort:'hybridrel', format:'json',
    });
    const data = await fetchJSON(`https://api.gdeltproject.org/api/v2/doc/doc?${params}`);
    const items = (data.articles||[]).map(a=>({ title:a.title, src:a.domain, url:a.url, time:a.seendate }));
    setCached(ck, items, 1_800_000);
    res.json(items);
  } catch(e){ res.status(500).json({error:e.message}); }
});
// ── /military-feed ────────────────────────────────────────────
app.get('/military-feed', auth, async (req, res) => {
  const ck = 'military_feed';
  const cached = getCached(ck);
  if (cached) return res.json(cached);
  try {
    const params = new URLSearchParams({
      query:'military naval carrier missile troops fighter',
      mode:'artlist', maxrecords:'15', timespan:'24h', sort:'hybridrel', format:'json',
    });
    const data = await fetchJSON(`https://api.gdeltproject.org/api/v2/doc/doc?${params}`);
    const items = (data.articles||[]).map(a=>({ title:a.title, src:a.domain, url:a.url, time:a.seendate }));
    setCached(ck, items, 1_800_000);
    res.json(items);
  } catch(e){ res.status(500).json({error:e.message}); }
});

// ── /ai ───────────────────────────────────────────────────────
app.post('/ai', auth, async (req, res) => {
  const { messages, max_tokens=400 } = req.body || {};
  if (!messages || !Array.isArray(messages)) {
    return res.status(400).json({ error:'messages array required', got: typeof messages });
  }
  const key = process.env.GROQ_API_KEY;
  if (!key) return res.status(503).json({ error:'GROQ_API_KEY not configured' });

  const ck = 'ai_' + Buffer.from(messages.map(m=>m.content).join('|')).toString('base64').slice(0,32);
  const cached = getCached(ck);
  if (cached) return res.json(cached);

  try {
    const r = await fetch('https://api.groq.com/openai/v1/chat/completions', {
      method:'POST',
      headers:{ 'Content-Type':'application/json', Authorization:`Bearer ${key}` },
      body: JSON.stringify({ model:'llama-3.3-70b-versatile', messages, max_tokens, temperature:0.3 }),
    });
    if (r.status===429) return res.status(429).json({error:'Groq rate limited'});
    if (!r.ok) throw new Error(`Groq ${r.status}`);
    const data = await r.json();
    setCached(ck, data, 600_000);
    res.json(data);
  } catch(e){ res.status(502).json({error:e.message}); }
});

// ============================================================
//  ARKA Quant Intelligence — Endpoints (merged from arka-quant-relay)
//  Auth: Bearer token via ARKA_API_KEY env var
//  /yahoo — sin auth (proxy público Yahoo Finance)
//  /api/* — Bearer auth
// ============================================================

// ── Quant auth middleware ─────────────────────────────────────
function quantAuth(req, res, next) {
  const QKEY = process.env.ARKA_API_KEY;
  if (!QKEY) return next(); // dev mode: sin key requerida
  const hdr = (req.headers['authorization'] || '').replace('Bearer ', '');
  if (hdr !== QKEY) return res.status(401).json({ error: 'Unauthorized' });
  next();
}

// ── Quant math helpers ────────────────────────────────────────
const qMean = arr => arr.reduce((a,b)=>a+b,0)/arr.length;
const qStd  = arr => { const m=qMean(arr); return Math.sqrt(arr.reduce((a,b)=>a+(b-m)**2,0)/arr.length); };
const logRet = closes => closes.slice(1).map((v,i)=>Math.log(v/closes[i]));

function linReg(x, y) {
  const n=x.length, mx=qMean(x), my=qMean(y);
  const ss=x.reduce((a,xi,i)=>({xy:a.xy+(xi-mx)*(y[i]-my),xx:a.xx+(xi-mx)**2}),{xy:0,xx:0});
  const slope=ss.xy/ss.xx, intercept=my-slope*mx;
  const pred=x.map(xi=>slope*xi+intercept);
  const res=y.map((yi,i)=>yi-pred[i]);
  const ssTot=y.reduce((a,yi)=>a+(yi-my)**2,0);
  const r2=1-res.reduce((a,r)=>a+r**2,0)/ssTot;
  return { pred, r2, stdRes:qStd(res), slope, intercept };
}

function garch11(rets) {
  const omega=0.000001,alpha=0.1,beta=0.85;
  let s2=Math.pow(qStd(rets),2);
  const v=[s2];
  for(let i=1;i<rets.length;i++){s2=omega+alpha*rets[i-1]**2+beta*s2;v.push(s2);}
  return {condVol:Math.sqrt(v[v.length-1]),alpha,beta};
}

// ── Yahoo Finance proxy ───────────────────────────────────────
async function fetchYahoo(ticker, range='1y', interval='1d') {
  const url=`https://query1.finance.yahoo.com/v8/finance/chart/${encodeURIComponent(ticker)}?range=${range}&interval=${interval}&includePrePost=false`;
  const r=await fetch(url,{headers:{'User-Agent':'Mozilla/5.0','Accept':'application/json','Referer':'https://finance.yahoo.com/'}});
  if(!r.ok) throw new Error(`Yahoo HTTP ${r.status}`);
  const json=await r.json();
  const result=json?.chart?.result?.[0];
  if(!result) throw new Error('No data from Yahoo');
  const ts=result.timestamp||[], cl=result.indicators?.quote?.[0]?.close||[];
  return ts.map((t,i)=>({date:new Date(t*1000).toISOString(),close:cl[i]})).filter(d=>d.close!=null);
}

// ── /yahoo — legacy proxy (sin auth, para gráficas) ──────────
app.get('/yahoo', async (req, res) => {
  const { ticker, range='1y', interval='1d' } = req.query;
  if (!ticker) return res.status(400).json({ error:'ticker required' });
  try {
    const url=`https://query1.finance.yahoo.com/v8/finance/chart/${encodeURIComponent(ticker)}?range=${range}&interval=${interval}&includePrePost=false&events=div%7Csplit`;
    const r=await fetch(url,{headers:{'User-Agent':'Mozilla/5.0','Accept':'application/json','Referer':'https://finance.yahoo.com/'}});
    if(!r.ok) throw new Error(`Yahoo HTTP ${r.status}`);
    res.json(await r.json());
  } catch(e) { res.status(500).json({ error:e.message }); }
});

// ── /api/fractal ──────────────────────────────────────────────
app.get('/api/fractal', quantAuth, async (req, res) => {
  const { ticker, range='1y' } = req.query;
  if (!ticker) return res.status(400).json({ error:'ticker required' });
  try {
    const interval=range==='1d'?'5m':range==='5d'?'1h':'1d';
    const data=await fetchYahoo(ticker,range,interval);
    if(data.length<10) return res.status(422).json({ error:'Insufficient data' });
    const closes=data.map(d=>d.close), x=closes.map((_,i)=>i);
    const {pred,r2,stdRes,slope}=linReg(x,closes);
    const last=closes[closes.length-1], lastPred=pred[pred.length-1];
    const hiIdx=closes.filter((c,i)=>c>pred[i]+stdRes).length;
    const loIdx=closes.filter((c,i)=>c<pred[i]-stdRes).length;
    let signal,signal_detail;
    if(last<lastPred-stdRes){signal='LONG_BIAS';signal_detail='Precio bajo −1σ — zona de valor, sesgo alcista';}
    else if(last>lastPred+stdRes){signal='SHORT_BIAS';signal_detail='Precio sobre +1σ — zona extendida, sesgo bajista';}
    else{signal='NEUTRAL';signal_detail='Precio dentro de bandas normales';}
    res.json({ticker,range,interval,observations:data.length,current_price:last,
      trend_today:lastPred,sigma:stdRes,r2,slope_direction:slope>0?'uptrend':'downtrend',
      price_vs_trend:last-lastPred,anomalies_hi:hiIdx,anomalies_lo:loIdx,
      signal,signal_detail,last_updated:data[data.length-1].date});
  } catch(e) { res.status(500).json({ error:e.message }); }
});

// ── /api/anomaly ──────────────────────────────────────────────
app.get('/api/anomaly', quantAuth, async (req, res) => {
  const { ticker, interval='5m', period='5d', z_threshold='2' } = req.query;
  if (!ticker) return res.status(400).json({ error:'ticker required' });
  try {
    const winSize=parseInt(req.query.window)||20, zThr=parseFloat(z_threshold)||2;
    const safeRange=period==='1d'?'5d':period;
    const data=await fetchYahoo(ticker,safeRange,interval);
    if(data.length<winSize+2) return res.status(422).json({ error:'Insufficient data' });
    const closes=data.map(d=>d.close), rets=logRet(closes);
    const zScores=[],anomHi=[],anomLo=[];
    for(let i=winSize;i<rets.length;i++){
      const win2=rets.slice(i-winSize,i), m=qMean(win2), s=qStd(win2)||1e-10, z=(rets[i]-m)/s;
      const bar={date:data[i+1].date,close:closes[i+1],lr:rets[i],z};
      zScores.push(bar);
      if(z>zThr) anomHi.push(bar);
      if(z<-zThr) anomLo.push(bar);
    }
    const lastZ=zScores[zScores.length-1];
    const allAnom=[...anomHi.map(a=>({...a,dir:'HI'})),...anomLo.map(a=>({...a,dir:'LO'}))]
      .sort((a,b)=>new Date(b.date)-new Date(a.date));
    let trigger,trigger_detail;
    if(lastZ&&lastZ.z<-zThr){trigger='LONG_TRIGGER';trigger_detail=`↓ LO ${interval} z=${lastZ.z.toFixed(2)}`;}
    else if(lastZ&&lastZ.z>zThr){trigger='SHORT_TRIGGER';trigger_detail=`↑ HI ${interval} z=+${lastZ.z.toFixed(2)}`;}
    else{trigger='NONE';trigger_detail='Sin anomalía en la última barra';}
    res.json({ticker,interval,period:safeRange,window:winSize,z_threshold:zThr,
      bars_analyzed:data.length,current_price:closes[closes.length-1],
      last_log_return:lastZ?.lr??null,last_zscore:lastZ?.z??null,
      anomalies_hi:anomHi.length,anomalies_lo:anomLo.length,
      trigger,trigger_detail,recent_anomalies:allAnom.slice(0,10),
      last_updated:data[data.length-1].date});
  } catch(e) { res.status(500).json({ error:e.message }); }
});

// ── /api/forecast ─────────────────────────────────────────────
app.get('/api/forecast', quantAuth, async (req, res) => {
  const { ticker, horizon='5', simulations='500' } = req.query;
  if (!ticker) return res.status(400).json({ error:'ticker required' });
  try {
    const H=Math.min(parseInt(horizon)||5,30), SIM=Math.min(parseInt(simulations)||500,2000);
    const data=await fetchYahoo(ticker,'1y','1d');
    if(data.length<30) return res.status(422).json({ error:'Insufficient data' });
    const closes=data.map(d=>d.close), rets=logRet(closes);
    const {condVol,alpha,beta}=garch11(rets);
    const lastPrice=closes[closes.length-1];
    const paths=[];
    for(let s=0;s<SIM;s++){
      let price=lastPrice,vol=condVol;
      for(let h=0;h<H;h++){
        const r=(Math.random()<0.5?1:-1)*Math.sqrt(-2*Math.log(Math.random()))*vol;
        price*=Math.exp(r); vol=Math.sqrt(0.000001+alpha*r*r+beta*vol*vol);
      }
      paths.push(price);
    }
    paths.sort((a,b)=>a-b);
    const pct=p=>paths[Math.floor(p/100*SIM)];
    const annualVol=condVol*Math.sqrt(252);
    const condition=annualVol<0.15?'LOW_VOLATILITY':annualVol<0.35?'NORMAL_VOLATILITY':'HIGH_VOLATILITY';
    res.json({ticker,horizon:H,simulations:SIM,current_price:lastPrice,
      garch:{conditional_vol:condVol,annual_vol:annualVol,alpha,beta,ab_sum:alpha+beta},
      condition,
      percentiles:{p5:pct(5),p10:pct(10),p25:pct(25),p50:pct(50),p75:pct(75),p90:pct(90),p95:pct(95)},
      expected_range:{low:pct(25),high:pct(75)},
      last_updated:data[data.length-1].date});
  } catch(e) { res.status(500).json({ error:e.message }); }
});

// ── /api/risk ─────────────────────────────────────────────────
app.get('/api/risk', quantAuth, async (req, res) => {
  const { ticker, capital='10000', risk_pct='1', sl_pips='10', rr='2', conviction='alta', fractal_range='1d' } = req.query;
  if (!ticker) return res.status(400).json({ error:'ticker required' });
  try {
    const cap=parseFloat(capital), pct=parseFloat(risk_pct), sl=parseFloat(sl_pips), rrV=parseFloat(rr);
    const convMult=conviction==='alta'?1:conviction==='media'?0.6:0.3;
    const frInterval=fractal_range==='1d'?'5m':fractal_range==='5d'?'1h':'1d';
    const [frData,yaData]=await Promise.all([fetchYahoo(ticker,fractal_range,frInterval),fetchYahoo(ticker,'5d','5m')]);
    const frC=frData.map(d=>d.close), frX=frC.map((_,i)=>i);
    const {pred,r2,stdRes}=linReg(frX,frC);
    const last=frC[frC.length-1], lastPred=pred[pred.length-1];
    let macroBias,macroDetail;
    if(last<lastPred-stdRes){macroBias='ALCISTA';macroDetail=`Bajo −1σ en ${fractal_range.toUpperCase()}`;}
    else if(last>lastPred+stdRes){macroBias='BAJISTA';macroDetail=`Sobre +1σ en ${fractal_range.toUpperCase()}`;}
    else{macroBias='NEUTRAL';macroDetail='Dentro de bandas normales';}
    const yaC=yaData.map(d=>d.close), yaR=logRet(yaC);
    let trigger='NONE',triggerDetail='Sin anomalía reciente',lastZ=null;
    if(yaR.length>20){
      const lr=yaR[yaR.length-1], ws=yaR.slice(-21,-1), m=qMean(ws), s=qStd(ws)||1e-10, z=(lr-m)/s;
      lastZ=z;
      if(z<-2){trigger='LONG_TRIGGER';triggerDetail=`↓ LO z=${z.toFixed(2)}`;}
      if(z>2){trigger='SHORT_TRIGGER';triggerDetail=`↑ HI z=+${z.toFixed(2)}`;}
    }
    const aligned=macroBias!=='NEUTRAL'&&trigger!=='NONE'&&
      ((macroBias==='ALCISTA'&&trigger==='LONG_TRIGGER')||(macroBias==='BAJISTA'&&trigger==='SHORT_TRIGGER'));
    const direction=aligned?(trigger==='LONG_TRIGGER'?'LONG':'SHORT'):'NO_TRADE';
    const condMult=r2>0.7?1:r2>0.4?0.8:0.5;
    const effPct=pct*convMult*condMult, riskUSD=cap*effPct/100, pipSz=last>100?0.01:0.0001;
    res.json({ticker,direction,confluence:aligned?'2/2':'0/2',
      macro:{bias:macroBias,detail:macroDetail,r2},
      anomaly:{trigger,detail:triggerDetail,last_zscore:lastZ},
      inputs:{capital:cap,risk_pct:pct,sl_pips:sl,rr:rrV,conviction},
      multipliers:{conviction:convMult,condition:condMult},
      sizing:{effective_risk_pct:effPct,risk_usd:riskUSD,profit_usd:riskUSD*rrV,
              size_lots:riskUSD/(sl*10),size_units:Math.round(riskUSD/sl),tp_pips:sl*rrV},
      take_profits:{
        tp1:{long:+(last+sl*pipSz).toFixed(4),short:+(last-sl*pipSz).toFixed(4)},
        tp2:{long:+(last+sl*2*pipSz).toFixed(4),short:+(last-sl*2*pipSz).toFixed(4)},
        tp3:{long:+(last+sl*3*pipSz).toFixed(4),short:+(last-sl*3*pipSz).toFixed(4)},
      }});
  } catch(e) { res.status(500).json({ error:e.message }); }
});

// ── /api/portfolio ────────────────────────────────────────────
app.get('/api/portfolio', quantAuth, async (req, res) => {
  const { tickers } = req.query;
  if (!tickers) return res.status(400).json({ error:'tickers required (comma separated)' });
  const list=tickers.split(',').map(t=>t.trim().toUpperCase()).filter(Boolean).slice(0,20);
  const results=await Promise.allSettled(list.map(async ticker => {
    const [d5,d20]=await Promise.all([fetchYahoo(ticker,'5d','1d'),fetchYahoo(ticker,'1mo','1d')]);
    if(!d5.length) throw new Error('No data');
    const c5=d5.map(d=>d.close), c20=d20.map(d=>d.close);
    const last=c5[c5.length-1], prev1=c5.length>1?c5[c5.length-2]:last, prev5=c5[0]||last;
    const vol=c20.length>1?(qStd(logRet(c20))*Math.sqrt(252)*100).toFixed(2):null;
    const trs=d5.slice(1).map((d,i)=>Math.abs(d.close-d5[i].close));
    const atr=trs.length>0?(qMean(trs.slice(-14))||qMean(trs)).toFixed(3):null;
    const {slope}=linReg(c5.map((_,i)=>i),c5);
    return {ticker,price:last,delta_1d:+((last-prev1)/prev1*100).toFixed(2),
            delta_5d:+((last-prev5)/prev5*100).toFixed(2),
            vol_20d:vol?parseFloat(vol):null,atr14:atr?parseFloat(atr):null,
            signal:slope>0.001?'ALCISTA':slope<-0.001?'BAJISTA':'NEUTRAL'};
  }));
  res.json({tickers:list,count:list.length,
    portfolio:results.map((r,i)=>r.status==='fulfilled'?r.value:{ticker:list[i],error:r.reason.message})});
});

// ── /api/snapshot ─────────────────────────────────────────────
app.get('/api/snapshot', quantAuth, async (req, res) => {
  const { ticker, capital='10000', risk_pct='1', sl_pips='10', rr='2', conviction='alta' } = req.query;
  if (!ticker) return res.status(400).json({ error:'ticker required' });
  try {
    const [frData,yaData]=await Promise.all([fetchYahoo(ticker,'1d','5m'),fetchYahoo(ticker,'5d','5m')]);
    const frC=frData.map(d=>d.close), frX=frC.map((_,i)=>i);
    const {pred,r2,stdRes}=linReg(frX,frC);
    const last=frC[frC.length-1], lastPred=pred[pred.length-1];
    const fs=last<lastPred-stdRes?'LONG_BIAS':last>lastPred+stdRes?'SHORT_BIAS':'NEUTRAL';
    const yaC=yaData.map(d=>d.close), yaR=logRet(yaC);
    let at='NONE',lz=null;
    if(yaR.length>20){const lr=yaR[yaR.length-1],ws=yaR.slice(-21,-1),m=qMean(ws),s=qStd(ws)||1e-10,z=(lr-m)/s;lz=z;if(z<-2)at='LONG_TRIGGER';if(z>2)at='SHORT_TRIGGER';}
    const aligned=fs!=='NEUTRAL'&&at!=='NONE'&&((fs==='LONG_BIAS'&&at==='LONG_TRIGGER')||(fs==='SHORT_BIAS'&&at==='SHORT_TRIGGER'));
    const direction=aligned?(at==='LONG_TRIGGER'?'LONG':'SHORT'):'NO_TRADE';
    const cap=parseFloat(capital), pct=parseFloat(risk_pct), sl=parseFloat(sl_pips), rrV=parseFloat(rr);
    const convMult=conviction==='alta'?1:conviction==='media'?0.6:0.3;
    const condMult=r2>0.7?1:r2>0.4?0.8:0.5;
    const effPct=pct*convMult*condMult, riskUSD=cap*effPct/100;
    res.json({ticker,timestamp:new Date().toISOString(),current_price:last,
      fractal:{signal:fs,r2,sigma:stdRes,trend:lastPred},
      anomaly:{trigger:at,last_zscore:lz},
      direction,confluence:aligned?'2/2':'0/2',
      position:{size_lots:+(riskUSD/(sl*10)).toFixed(2),size_units:Math.round(riskUSD/sl),
                risk_usd:+riskUSD.toFixed(2),profit_usd:+(riskUSD*rrV).toFixed(2),effective_risk_pct:+effPct.toFixed(3)}});
  } catch(e) { res.status(500).json({ error:e.message }); }
});

// ── /api/chat — Anthropic Claude proxy para Quant ─────────────
app.post('/api/chat', quantAuth, async (req, res) => {
  const ANTHROPIC_KEY = process.env.ANTHROPIC_API_KEY;
  if (!ANTHROPIC_KEY) return res.status(500).json({ error:'ANTHROPIC_API_KEY not configured' });
  const { system, messages } = req.body;
  if (!messages?.length) return res.status(400).json({ error:'messages required' });
  try {
    const r = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: { 'Content-Type':'application/json', 'x-api-key':ANTHROPIC_KEY, 'anthropic-version':'2023-06-01' },
      body: JSON.stringify({
        model: 'claude-sonnet-4-20250514',
        max_tokens: 1024,
        system: system || 'Eres el asistente de trading de ARKA.',
        messages,
      }),
    });
    if (!r.ok) { const err=await r.json(); return res.status(r.status).json({ error:err.error?.message||`Anthropic ${r.status}` }); }
    const data = await r.json();
    res.json({ content: data.content?.[0]?.text || '' });
  } catch(e) { res.status(500).json({ error:e.message }); }
});

app.listen(PORT, () => {
  console.log(`ARKA Relay v18 on :${PORT} | Auth:${SECRET?'ON':'OFF'} | RateLimit:OFF`);
});
