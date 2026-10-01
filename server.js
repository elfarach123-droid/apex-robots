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

// ============= ROUTES UTILISATEURS =============

app.post('/api/register', async (req, res) => {
  try {
    const { name, phone, password } = req.body;
    if (!name || !phone || !password) return res.status(400).json({ error: 'Champs manquants' });
    if (!/^6\d{8}$/.test(phone)) return res.status(400).json({ error: 'Numéro invalide' });
    if (password.length < 6) return res.status(400).json({ error: 'Mot de passe trop court' });

    const { data: existing } = await supabase
      .from('users').select('id').eq('phone', phone).maybeSingle();
    if (existing) return res.status(409).json({ error: 'Ce numéro a déjà un compte' });

    const password_hash = await bcrypt.hash(password, 10);

    const { data, error } = await supabase
      .from('users')
      .insert([{ name, phone, password_hash }])
      .select('id, name, phone, created_at')
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
      .from('users').select('*').eq('phone', phone).maybeSingle();
    if (!user) return res.status(401).json({ error: 'Numéro ou mot de passe incorrect' });

    const ok = await bcrypt.compare(password, user.password_hash);
    if (!ok) return res.status(401).json({ error: 'Numéro ou mot de passe incorrect' });

    res.json({ success: true, user: { id: user.id, name: user.name, phone: user.phone } });
  } catch (e) {
    console.error('Erreur login:', e);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

// ============= ROUTES COMMANDES =============

app.post('/api/orders', async (req, res) => {
  try {
    const { user_id, plan_id, plan_name, total, method, phone, reference } = req.body;
    const { data, error } = await supabase
      .from('orders')
      .insert([{ user_id, plan_id, plan_name, total, method, phone, reference, status: 'pending' }])
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