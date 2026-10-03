require('dotenv').config();
const express = require('express');
const helmet = require('helmet');
const compression = require('compression');
const rateLimit = require('express-rate-limit');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const { createClient } = require('@supabase/supabase-js');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;
app.set('trust proxy', 1);

app.use(helmet({ contentSecurityPolicy: false, crossOriginEmbedderPolicy: false }));
app.use(compression());
app.use(rateLimit({ windowMs: 15 * 60 * 1000, max: 300 }));
app.use(express.json({ limit: '1mb' }));
app.use(express.static(__dirname, { maxAge: '1d', etag: true }));

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_KEY
);

// ============= NOTIFICATION WHATSAPP =============
async function notifyPromoter(message){
  try {
    const key = process.env.CALLMEBOT_API_KEY;
    const phone = process.env.PROMOTER_WHATSAPP;
    if (!key || !phone || key.trim() === '') {
      console.log('📵 CallMeBot non configuré');
      return;
    }
    const url = `https://api.callmebot.com/whatsapp.php?phone=${encodeURIComponent(phone)}&text=${encodeURIComponent(message)}&apikey=${encodeURIComponent(key)}`;
    const r = await fetch(url);
    if (r.ok) console.log('📱 Notif WhatsApp envoyée');
  } catch (e) { console.error('Erreur notif:', e.message); }
}

// ============= SESSION ADMIN (en mémoire) =============
const adminSessions = new Map();
const SESSION_DURATION = 24 * 60 * 60 * 1000;

function createAdminSession(){
  const token = crypto.randomBytes(32).toString('hex');
  adminSessions.set(token, Date.now() + SESSION_DURATION);
  return token;
}
function checkAdminSession(token){
  if (!token) return false;
  const expires = adminSessions.get(token);
  if (!expires) return false;
  if (Date.now() > expires) { adminSessions.delete(token); return false; }
  return true;
}
function adminAuth(req, res, next){
  const token = req.headers.authorization?.replace('Bearer ', '') || req.query.token;
  if (!checkAdminSession(token)) {
    return res.status(401).json({ error: 'Non autorisé' });
  }
  next();
}

// ============= ANTI-FRAUDE =============
const SUSPECT_PATTERNS = [
  /(?:script|select|insert|update|delete|drop|union|exec)/i,
  /[<>{}\[\]\\]/,
  /(.)\1{5,}/
];
function isSuspect(value){
  if (!value) return false;
  const v = String(value).trim();
  if (v.length < 2 || v.length > 80) return true;
  for (const p of SUSPECT_PATTERNS) if (p.test(v)) return true;
  return false;
}
function validateRegistration({ name, phone, password, country, city }){
  const errors = [];
  if (!name || isSuspect(name)) errors.push('invalid_name');
  if (!country || isSuspect(country)) errors.push('invalid_country');
  if (!city || isSuspect(city)) errors.push('invalid_city');
  const phoneFormats = {
    'CM': { len: 9,  prefix: '6' },
    'CI': { len: 10, prefix: ''  },
    'SN': { len: 9,  prefix: '7' },
    'GA': { len: 8,  prefix: ''  },
    'TD': { len: 8,  prefix: '6' }
  };
  const fmt = phoneFormats[country] || { len: 9, prefix: '' };
  const digits = String(phone || '').replace(/\D/g, '');
  if (!digits || digits.length !== fmt.len) errors.push('invalid_phone');
  if (fmt.prefix && !digits.startsWith(fmt.prefix)) errors.push('invalid_phone');
  if (!password || password.length < 5) errors.push('weak_password');
  if (!/[a-zA-Z]/.test(password)) errors.push('weak_password');
  if (!/\d/.test(password)) errors.push('weak_password');
  return errors;
}
function generateReferralCode(){
  const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  let code = '';
  for (let i = 0; i < 6; i++) code += chars[Math.floor(Math.random() * chars.length)];
  return code;
}

// ============= ROUTES PUBLIQUES =============

app.post('/api/register', async (req, res) => {
  try {
    const { name, phone, password, country, city, referralCode } = req.body;
    const errors = validateRegistration({ name, phone, password, country, city });
    if (errors.length) return res.status(400).json({ error: 'Vérification de sécurité échouée' });

    const { data: existing } = await supabase.from('users').select('id').eq('phone', phone).maybeSingle();
    if (existing) return res.status(409).json({ error: 'Ce numéro a déjà un compte' });

    let referred_by = null;
    if (referralCode) {
      const rc = String(referralCode).trim().toUpperCase();
      const { data: sponsor } = await supabase.from('users').select('id').eq('referral_code', rc).maybeSingle();
      if (sponsor) referred_by = sponsor.id;
    }

    let myReferralCode = null;
    for (let i = 0; i < 5; i++) {
      const candidate = generateReferralCode();
      const { data: clash } = await supabase.from('users').select('id').eq('referral_code', candidate).maybeSingle();
      if (!clash) { myReferralCode = candidate; break; }
    }
    if (!myReferralCode) myReferralCode = generateReferralCode() + Date.now().toString(36).slice(-2).toUpperCase();

    const password_hash = await bcrypt.hash(password, 10);

    const { data, error } = await supabase
      .from('users')
      .insert([{ name, phone, password_hash, country: country || 'CM', city: city || '', referral_code: myReferralCode, referred_by }])
      .select('id, name, phone, country, city, referral_code, referred_by, created_at')
      .single();

    if (error) throw error;
    notifyPromoter(`🆕 NOUVELLE INSCRIPTION\n\n👤 ${name}\n📱 ${phone}\n🌍 ${country} - ${city}\n🎟️ Code : ${myReferralCode}${referred_by ? '\n✅ Parrainé' : ''}`);

    res.json({ success: true, user: data });
  } catch (e) {
    console.error('Erreur register:', e);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

app.post('/api/login', async (req, res) => {
  try {
    const { phone, password } = req.body;
    if (!phone || !password) return res.status(400).json({ error: 'Champs manquants' });
    const { data: user } = await supabase.from('users').select('*').eq('phone', phone).maybeSingle();
    if (!user) return res.status(401).json({ error: 'Numéro ou mot de passe incorrect' });
    const ok = await bcrypt.compare(password, user.password_hash);
    if (!ok) return res.status(401).json({ error: 'Numéro ou mot de passe incorrect' });
    res.json({
      success: true,
      user: {
        id: user.id, name: user.name, phone: user.phone,
        country: user.country || 'CM', city: user.city || '',
        referral_code: user.referral_code || null
      }
    });
  } catch (e) {
    console.error('Erreur login:', e);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

app.post('/api/orders', async (req, res) => {
  try {
    const { user_id, plan_id, plan_name, total, method, phone, reference } = req.body;
    const { data: user } = await supabase.from('users').select('id').eq('id', user_id).maybeSingle();
    if (!user) return res.status(400).json({ error: 'Utilisateur introuvable' });
    if (isSuspect(phone)) return res.status(400).json({ error: 'Numéro invalide' });

    const { data, error } = await supabase
      .from('orders')
      .insert([{ user_id, plan_id, plan_name, total, method, phone, reference, status: 'pending' }])
      .select()
      .single();
    if (error) throw error;

    const { data: buyer } = await supabase.from('users').select('name, phone, country').eq('id', user_id).maybeSingle();
    notifyPromoter(`💰 NOUVELLE COMMANDE\n\n🤖 ${plan_name}\n💵 ${total} FCFA\n👤 ${buyer?.name || '?'}\n📱 ${buyer?.phone || phone}\n🌍 ${buyer?.country || '?'}`);

    res.json({ success: true, order: data });
  } catch (e) {
    console.error('Erreur orders:', e);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

app.get('/api/orders/:userId', async (req, res) => {
  try {
    const { data, error } = await supabase
      .from('orders')
      .select('*')
      .eq('user_id', req.params.userId)
      .order('created_at', { ascending: false });
    if (error) throw error;
    res.json(data || []);
  } catch (e) {
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

app.get('/api/referral-stats/:userId', async (req, res) => {
  try {
    const userId = req.params.userId;
    const { data: me } = await supabase.from('users').select('referral_code').eq('id', userId).maybeSingle();
    if (!me) return res.status(404).json({ error: 'Utilisateur introuvable' });
    const { data: filleuls } = await supabase.from('users').select('id').eq('referred_by', userId);
    const filleulIds = (filleuls || []).map(f => f.id);
    let totalCommission = 0, totalOrders = 0;
    if (filleulIds.length) {
      const { data: orders } = await supabase.from('orders').select('total, status').in('user_id', filleulIds).in('status', ['paid', 'active', 'completed']);
      orders?.forEach(() => { totalCommission += 1000; totalOrders++; });
    }
    res.json({
      success: true, referral_code: me.referral_code,
      filleuls_count: filleulIds.length,
      orders_count: totalOrders,
      commission_earned: totalCommission
    });
  } catch (e) {
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

app.post('/api/referral-request', async (req, res) => {
  try {
    const { user_id, amount } = req.body;
    if (!user_id || !amount) return res.status(400).json({ error: 'Champs manquants' });
    const { data: user } = await supabase.from('users').select('name, phone, country').eq('id', user_id).maybeSingle();
    if (!user) return res.status(404).json({ error: 'Utilisateur introuvable' });
    notifyPromoter(`💸 DEMANDE RETRAIT PARRAINAGE\n\n👤 ${user.name}\n📱 ${user.phone}\n🌍 ${user.country}\n💰 Montant : ${amount} FCFA`);
    res.json({ success: true });
  } catch (e) {
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

// ============= ROUTES ADMIN =============

// Servir la page admin (URL secrète)
app.get('/admin-console', (req, res) => {
  res.sendFile(path.join(__dirname, 'admin.html'));
});

// Login admin
app.post('/admin-api/login', (req, res) => {
  try {
    const { phone, password } = req.body;
    const ADMIN_PHONE = process.env.ADMIN_PHONE;
    const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;

    if (!ADMIN_PHONE || !ADMIN_PASSWORD) {
      return res.status(500).json({ error: 'Admin non configuré' });
    }
    if (String(phone).trim() !== ADMIN_PHONE || String(password) !== ADMIN_PASSWORD) {
      return res.status(401).json({ error: 'Identifiants incorrects' });
    }
    const token = createAdminSession();
    res.json({ success: true, token });
  } catch (e) {
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

// Logout admin
app.post('/admin-api/logout', adminAuth, (req, res) => {
  const token = req.headers.authorization?.replace('Bearer ', '');
  adminSessions.delete(token);
  res.json({ success: true });
});

// Vérifier session
app.get('/admin-api/check', adminAuth, (req, res) => {
  res.json({ success: true });
});

// Stats globales
app.get('/admin-api/stats', adminAuth, async (req, res) => {
  try {
    const { data: users } = await supabase.from('users').select('id, created_at');
    const { data: orders } = await supabase.from('orders').select('total, status, created_at');

    const totalUsers = users?.length || 0;
    const totalOrders = orders?.length || 0;
    const pending = orders?.filter(o => o.status === 'pending').length || 0;
    const paid = orders?.filter(o => ['paid','active','completed'].includes(o.status)).length || 0;
    const rejected = orders?.filter(o => o.status === 'rejected').length || 0;
    const revenue = orders?.filter(o => ['paid','active','completed'].includes(o.status)).reduce((s, o) => s + (o.total || 0), 0) || 0;

    res.json({
      success: true,
      totalUsers, totalOrders, pending, paid, rejected, revenue
    });
  } catch (e) {
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

// Liste des commandes (avec nom + phone user)
app.get('/admin-api/orders', adminAuth, async (req, res) => {
  try {
    const statusFilter = req.query.status || 'all';
    let query = supabase.from('orders').select('*').order('created_at', { ascending: false });
    if (statusFilter !== 'all') query = query.eq('status', statusFilter);

    const { data: orders } = await query;
    if (!orders || !orders.length) return res.json({ success: true, orders: [] });

    // Charger les users correspondants
    const userIds = [...new Set(orders.map(o => o.user_id))];
    const { data: users } = await supabase.from('users').select('id, name, phone, country, city, referral_code').in('id', userIds);
    const usersMap = {};
    users?.forEach(u => { usersMap[u.id] = u; });

    const enriched = orders.map(o => ({
      ...o,
      user: usersMap[o.user_id] || null
    }));

    res.json({ success: true, orders: enriched });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

// Changer le statut d'une commande
app.post('/admin-api/order/:id/status', adminAuth, async (req, res) => {
  try {
    const { id } = req.params;
    const { status } = req.body;
    if (!['pending','paid','active','completed','rejected'].includes(status)) {
      return res.status(400).json({ error: 'Statut invalide' });
    }
    const update = { status };
    if (status === 'paid') update.paid_at = new Date().toISOString();

    const { error } = await supabase.from('orders').update(update).eq('id', id);
    if (error) throw error;
    res.json({ success: true });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

// Liste des utilisateurs
app.get('/admin-api/users', adminAuth, async (req, res) => {
  try {
    const { data: users } = await supabase
      .from('users')
      .select('id, name, phone, country, city, referral_code, referred_by, created_at')
      .order('created_at', { ascending: false });

    // Récupérer les parrains
    const allIds = users?.map(u => u.id) || [];
    const { data: sponsors } = await supabase.from('users').select('id, name, phone').in('id', allIds);
    const sponsorsMap = {};
    sponsors?.forEach(s => { sponsorsMap[s.id] = s; });

    const enriched = (users || []).map(u => ({
      ...u,
      sponsor: u.referred_by ? sponsorsMap[u.referred_by] : null
    }));

    res.json({ success: true, users: enriched });
  } catch (e) {
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

// Top parrains (classement parrainage)
app.get('/admin-api/referrals', adminAuth, async (req, res) => {
  try {
    const { data: users } = await supabase
      .from('users')
      .select('id, name, phone, referral_code, referred_by');

    const counts = {};
    users?.forEach(u => {
      if (u.referred_by) {
        counts[u.referred_by] = (counts[u.referred_by] || 0) + 1;
      }
    });

    const usersMap = {};
    users?.forEach(u => { usersMap[u.id] = u; });

    const ranking = Object.entries(counts)
      .map(([id, count]) => ({
        id,
        name: usersMap[id]?.name || '?',
        phone: usersMap[id]?.phone || '?',
        code: usersMap[id]?.referral_code || '?',
        filleuls: count,
        commission: count * 1000
      }))
      .sort((a, b) => b.filleuls - a.filleuls);

    res.json({ success: true, ranking });
  } catch (e) {
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

// ============= PAIEMENT (à activer plus tard) =============
app.post('/api/payer', async (req, res) => {
  res.status(503).json({ error: 'Paiement automatique en cours d\'activation.' });
});

// ============= SERVIR LE SITE =============
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

app.use((err, req, res, next) => {
  console.error('Erreur serveur:', err.message);
  res.status(500).send('Erreur serveur');
});

app.listen(PORT, () => {
  console.log(`✅ Apex Robots en ligne sur http://localhost:${PORT}`);
  console.log(`🗄️  Base de données : Supabase connectée`);
  console.log(`📱 Notifications : ${process.env.CALLMEBOT_API_KEY ? 'WhatsApp actif' : 'désactivées'}`);
  console.log(`🔒 Admin : ${process.env.ADMIN_PHONE ? 'configuré' : 'NON CONFIGURÉ'}`);
});