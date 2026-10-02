require('dotenv').config();
const express = require('express');
const helmet = require('helmet');
const compression = require('compression');
const rateLimit = require('express-rate-limit');
const bcrypt = require('bcryptjs');
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

// ============= SUPABASE =============
const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_KEY
);

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
  if (!phone || !/^6\d{8}$/.test(phone)) errors.push('invalid_phone');
  if (!password || password.length < 6 || /^\d+$/.test(password)) errors.push('weak_password');
  if (!country || isSuspect(country)) errors.push('invalid_country');
  if (!city || isSuspect(city)) errors.push('invalid_city');
  return errors;
}

// ============= ROUTES UTILISATEURS =============

app.post('/api/register', async (req, res) => {
  try {
    const { name, phone, password, country, city } = req.body;

    // Anti-fraude
    const errors = validateRegistration({ name, phone, password, country, city });
    if (errors.length) {
      console.warn('Anti-fraude bloqué:', errors, { phone, country });
      return res.status(400).json({ error: 'Vérification de sécurité échouée' });
    }

    // Vérifier si le numéro existe déjà
    const { data: existing } = await supabase
      .from('users')
      .select('id')
      .eq('phone', phone)
      .maybeSingle();

    if (existing) return res.status(409).json({ error: 'Ce numéro a déjà un compte' });

    // Hasher le mot de passe
    const password_hash = await bcrypt.hash(password, 10);

    // Insérer (les colonnes country et city doivent exister dans la table users)
    const { data, error } = await supabase
      .from('users')
      .insert([{ name, phone, password_hash, country: country || 'CM', city: city || '' }])
      .select('id, name, phone, country, city, created_at')
      .single();

    if (error) throw error;
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

    const { data: user } = await supabase
      .from('users')
      .select('*')
      .eq('phone', phone)
      .maybeSingle();

    if (!user) return res.status(401).json({ error: 'Numéro ou mot de passe incorrect' });

    const ok = await bcrypt.compare(password, user.password_hash);
    if (!ok) return res.status(401).json({ error: 'Numéro ou mot de passe incorrect' });

    res.json({
      success: true,
      user: {
        id: user.id,
        name: user.name,
        phone: user.phone,
        country: user.country || 'CM',
        city: user.city || ''
      }
    });
  } catch (e) {
    console.error('Erreur login:', e);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

// ============= ROUTES COMMANDES =============

app.post('/api/orders', async (req, res) => {
  try {
    const { user_id, plan_id, plan_name, total, method, phone, reference } = req.body;

    // Anti-fraude : vérifier que l'utilisateur existe
    const { data: user } = await supabase
      .from('users')
      .select('id')
      .eq('id', user_id)
      .maybeSingle();

    if (!user) return res.status(400).json({ error: 'Utilisateur introuvable' });

    if (isSuspect(phone)) return res.status(400).json({ error: 'Numéro invalide' });

    const { data, error } = await supabase
      .from('orders')
      .insert([{
        user_id, plan_id, plan_name, total,
        method, phone, reference,
        status: 'pending'
      }])
      .select()
      .single();

    if (error) throw error;
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
    console.error('Erreur GET orders:', e);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

// ============= PAIEMENT (à activer plus tard) =============
app.post('/api/payer', async (req, res) => {
  res.status(503).json({
    error: 'Paiement automatique en cours d\'activation. Contacte le support.'
  });
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
  console.log(`💳 Paiement : en attente d'activation`);
});