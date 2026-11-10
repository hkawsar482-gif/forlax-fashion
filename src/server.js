'use strict';

require('dotenv').config();

const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const { createClient } = require('@supabase/supabase-js');

const app = express();
const PORT = Number(process.env.PORT) || 3000;

// -----------------------------------------------------------------------------
// ENVIRONMENT / DATABASE
// -----------------------------------------------------------------------------
const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_SERVICE_ROLE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY;
const configuredOrigins = (process.env.CORS_ORIGIN || '*')
  .split(',')
  .map((value) => value.trim())
  .filter(Boolean);

const supabase = SUPABASE_URL && SUPABASE_SERVICE_ROLE_KEY
  ? createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY, {
      auth: {
        autoRefreshToken: false,
        persistSession: false,
        detectSessionInUrl: false
      }
    })
  : null;

// -----------------------------------------------------------------------------
// MIDDLEWARE
// -----------------------------------------------------------------------------
app.disable('x-powered-by');
app.use(helmet());
app.use(cors({
  origin(origin, callback) {
    // No Origin is normal for health checks and server-to-server requests.
    if (!origin || configuredOrigins.includes('*') || configuredOrigins.includes(origin)) {
      return callback(null, true);
    }
    return callback(new Error('This website origin is not allowed by CORS.'));
  },
  methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'apikey'],
  credentials: false,
  optionsSuccessStatus: 204
}));
app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: true, limit: '1mb' }));

const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 200,
  standardHeaders: 'draft-7',
  legacyHeaders: false,
  message: {
    success: false,
    error: 'অনেকবার অনুরোধ করা হয়েছে। কিছুক্ষণ পর আবার চেষ্টা করুন।'
  }
});
app.use('/api', apiLimiter);

// -----------------------------------------------------------------------------
// HELPERS
// -----------------------------------------------------------------------------
function requireDatabase(res) {
  if (supabase) return true;
  res.status(503).json({
    success: false,
    error: 'সার্ভারের Database সেটআপ সম্পন্ন হয়নি। Render Environment Variables পরীক্ষা করুন।'
  });
  return false;
}

function cleanText(value, maxLength = 500) {
  return String(value ?? '').trim().slice(0, maxLength);
}

function normalizePhone(value) {
  const banglaDigits = '০১২৩৪৫৬৭৮৯';
  let phone = String(value ?? '').replace(/[০-৯]/g, (digit) => String(banglaDigits.indexOf(digit)));
  phone = phone.replace(/\D/g, '');
  // Accept Bangladesh international format (8801XXXXXXXXX) and local format.
  if (phone.startsWith('880') && phone.length === 13) phone = `0${phone.slice(3)}`;
  else if (phone.startsWith('88') && phone.length === 13) phone = phone.slice(2);
  return phone;
}

function isDhakaDistrict(value) {
  const district = cleanText(value, 100).toLowerCase();
  return district === 'dhaka' || district.includes('ঢাকার ভিতরে') || district.includes('inside dhaka');
}

function getBaseProductName(productName, size) {
  let name = cleanText(productName, 250);
  const selectedSize = cleanText(size, 30);
  if (selectedSize) {
    const escaped = selectedSize.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    name = name.replace(new RegExp(`\\s*\\(${escaped}\\)\\s*$`, 'i'), '').trim();
  }
  return name.replace(/\s*\((M|L|XL|XXL)\)\s*$/i, '').trim();
}

function getProductImage(product) {
  if (product.image) return product.image;
  if (Array.isArray(product.images) && product.images.length > 0) {
    const first = product.images[0];
    return typeof first === 'string' ? first : (first?.url || first?.image_url || null);
  }
  return null;
}

function sendDatabaseError(res, label, error) {
  console.error(`${label}:`, error?.message || error);
  return res.status(500).json({
    success: false,
    error: label
  });
}

function getBearerToken(req) {
  const header = cleanText(req.headers.authorization, 2000);
  const match = header.match(/^Bearer\s+(.+)$/i);
  return match ? match[1] : null;
}

async function requireAdmin(req, res, next) {
  if (!requireDatabase(res)) return;
  const token = getBearerToken(req);
  if (!token) {
    return res.status(401).json({ success: false, error: 'Admin login required.' });
  }

  try {
    const { data: authData, error: authError } = await supabase.auth.getUser(token);
    if (authError || !authData?.user) {
      return res.status(401).json({ success: false, error: 'Admin session is invalid or expired.' });
    }

    const { data: profile, error: profileError } = await supabase
      .from('admin_profiles')
      .select('role, is_active')
      .eq('user_id', authData.user.id)
      .maybeSingle();

    if (profileError) return sendDatabaseError(res, 'Could not verify admin permission.', profileError);
    if (!profile || profile.is_active !== true || !['admin', 'owner', 'super_admin'].includes(profile.role)) {
      return res.status(403).json({ success: false, error: 'This account does not have admin permission.' });
    }

    req.adminUser = authData.user;
    req.adminProfile = profile;
    return next();
  } catch (error) {
    console.error('Admin authorization error:', error?.message || error);
    return res.status(401).json({ success: false, error: 'Could not verify admin session.' });
  }
}

// -----------------------------------------------------------------------------
// BASIC / HEALTH
// -----------------------------------------------------------------------------
app.get('/', (req, res) => {
  res.json({
    success: true,
    message: 'ForLax Fashion API is running.',
    version: '2.0.0'
  });
});

app.get('/api/health', async (req, res) => {
  if (!requireDatabase(res)) return;
  try {
    const { error } = await supabase
      .from('delivery_settings')
      .select('id')
      .eq('id', 1)
      .maybeSingle();

    if (error) {
      console.error('Health check database error:', error.message);
      return res.status(503).json({ success: false, server: 'online', database: 'error' });
    }

    return res.json({
      success: true,
      server: 'online',
      database: 'connected',
      timestamp: new Date().toISOString()
    });
  } catch (error) {
    console.error('Health check failed:', error?.message || error);
    return res.status(503).json({ success: false, server: 'online', database: 'error' });
  }
});

// -----------------------------------------------------------------------------
// STOREFRONT DATA
// Response matches the existing XML: { success, content, products }
// -----------------------------------------------------------------------------
app.get('/api/store-data', async (req, res) => {
  if (!requireDatabase(res)) return;
  try {
    const [contentResult, productsResult, deliveryResult] = await Promise.all([
      supabase.from('site_content').select('content_key, content_value'),
      supabase
        .from('products')
        .select('id, product_code, category_id, name, description, regular_price, price, image, images, sizes, colors, stock, is_active, sort_order')
        .eq('is_active', true)
        .order('sort_order', { ascending: true })
        .order('created_at', { ascending: false }),
      supabase
        .from('delivery_settings')
        .select('inside_dhaka_charge, outside_dhaka_charge, free_delivery_min_quantity')
        .eq('id', 1)
        .maybeSingle()
    ]);

    if (contentResult.error) return sendDatabaseError(res, 'ওয়েবসাইটের সেটিংস লোড করা যায়নি।', contentResult.error);
    if (productsResult.error) return sendDatabaseError(res, 'পণ্যের তালিকা লোড করা যায়নি।', productsResult.error);
    if (deliveryResult.error) return sendDatabaseError(res, 'ডেলিভারি সেটিংস লোড করা যায়নি।', deliveryResult.error);

    const content = {};
    for (const row of contentResult.data || []) {
      content[row.content_key] = row.content_value;
    }

    // Keep the XML bill calculator aligned with the delivery settings table.
    const delivery = deliveryResult.data || {};
    if (content.del_inside_charge === undefined) {
      content.del_inside_charge = Number(delivery.inside_dhaka_charge ?? 60);
    }
    if (content.del_outside_charge === undefined) {
      content.del_outside_charge = Number(delivery.outside_dhaka_charge ?? 120);
    }

    const products = (productsResult.data || []).map((product) => ({
      ...product,
      image: getProductImage(product) || '',
      size: ''
    }));

    return res.json({ success: true, content, products });
  } catch (error) {
    return sendDatabaseError(res, 'Store data load failed.', error);
  }
});

// -----------------------------------------------------------------------------
// INCOMPLETE ORDER LEAD
// Existing XML sends customer_name, customer_phone, shipping_district,
// shipping_address to this endpoint.
// -----------------------------------------------------------------------------
app.post('/api/incomplete-order', async (req, res) => {
  if (!requireDatabase(res)) return;

  const customerName = cleanText(req.body?.customer_name, 150);
  const customerPhone = normalizePhone(req.body?.customer_phone);
  const shippingDistrict = cleanText(req.body?.shipping_district, 100);
  const shippingAddress = cleanText(req.body?.shipping_address, 1000);

  if (customerPhone.length !== 11) {
    return res.status(400).json({ success: false, error: 'সঠিক ১১ ডিজিটের মোবাইল নম্বর প্রয়োজন।' });
  }

  try {
    const { data, error } = await supabase
      .from('incomplete_orders')
      .insert({
        customer_name: customerName || null,
        customer_phone: customerPhone,
        shipping_district: shippingDistrict || null,
        shipping_address: shippingAddress || null
      })
      .select('id')
      .single();

    if (error) return sendDatabaseError(res, 'অসম্পূর্ণ অর্ডার সংরক্ষণ করা যায়নি।', error);
    return res.status(201).json({ success: true, lead_id: data.id });
  } catch (error) {
    return sendDatabaseError(res, 'অসম্পূর্ণ অর্ডার সংরক্ষণ করা যায়নি।', error);
  }
});

// -----------------------------------------------------------------------------
// CHECKOUT
// The browser-sent price is ignored. Price is read from Supabase products.
// Existing XML expects: success, order_number, grand_total.
// -----------------------------------------------------------------------------
app.post('/api/checkout', async (req, res) => {
  if (!requireDatabase(res)) return;

  const customerName = cleanText(req.body?.customer_name, 150);
  const customerPhone = normalizePhone(req.body?.customer_phone);
  const shippingDistrict = cleanText(req.body?.shipping_district, 100);
  const shippingAddress = cleanText(req.body?.shipping_address, 1000);
  const clientRequestId = cleanText(req.body?.client_request_id, 120) || null;
  const requestedItems = Array.isArray(req.body?.items) ? req.body.items : [];

  if (!customerName) return res.status(400).json({ success: false, error: 'কাস্টমারের নাম প্রয়োজন।' });
  if (customerPhone.length !== 11) return res.status(400).json({ success: false, error: 'সঠিক ১১ ডিজিটের মোবাইল নম্বর প্রয়োজন।' });
  if (!shippingDistrict || !shippingAddress) {
    return res.status(400).json({ success: false, error: 'ডেলিভারি এলাকা ও সম্পূর্ণ ঠিকানা প্রয়োজন।' });
  }
  if (requestedItems.length < 1 || requestedItems.length > 30) {
    return res.status(400).json({ success: false, error: '১ থেকে ৩০টি পণ্য নির্বাচন করুন।' });
  }

  try {
    // Idempotency: same client request must not create a second order.
    if (clientRequestId) {
      const { data: existingOrder, error: existingError } = await supabase
        .from('orders')
        .select('order_number, grand_total')
        .eq('client_request_id', clientRequestId)
        .maybeSingle();

      if (existingError) return sendDatabaseError(res, 'আগের অর্ডার যাচাই করা যায়নি।', existingError);
      if (existingOrder) {
        return res.json({
          success: true,
          duplicate: true,
          order_number: existingOrder.order_number,
          grand_total: Number(existingOrder.grand_total)
        });
      }
    }

    // Validate item names and quantities. Never accept price from the browser.
    const normalizedItems = [];
    for (const item of requestedItems) {
      const quantity = Number(item?.quantity);
      const size = cleanText(item?.size, 30) || 'Standard';
      const productName = getBaseProductName(item?.product_name, size);
      if (!productName || !Number.isInteger(quantity) || quantity < 1 || quantity > 50) {
        return res.status(400).json({ success: false, error: 'একটি পণ্যের নাম, সাইজ অথবা পরিমাণ সঠিক নয়।' });
      }
      normalizedItems.push({ productName, size, quantity });
    }

    const productNames = [...new Set(normalizedItems.map((item) => item.productName))];
    const { data: products, error: productsError } = await supabase
      .from('products')
      .select('id, name, price, image, images, is_active')
      .in('name', productNames)
      .eq('is_active', true);

    if (productsError) return sendDatabaseError(res, 'পণ্যের দাম যাচাই করা যায়নি।', productsError);

    const productMap = new Map();
    for (const product of products || []) {
      if (productMap.has(product.name)) {
        return res.status(409).json({ success: false, error: `একই নামে একাধিক পণ্য আছে: ${product.name}` });
      }
      productMap.set(product.name, product);
    }

    const missingProduct = productNames.find((name) => !productMap.has(name));
    if (missingProduct) {
      return res.status(409).json({
        success: false,
        error: `পণ্যটি নতুন Products তালিকায় পাওয়া যায়নি: ${missingProduct}। আগে Admin Panel বা Database থেকে পণ্যটি যোগ করুন।`
      });
    }

    const pricedItems = normalizedItems.map((item) => {
      const product = productMap.get(item.productName);
      const unitPrice = Number(product.price);
      if (!Number.isFinite(unitPrice) || unitPrice < 0) {
        throw new Error(`Invalid database price for ${item.productName}`);
      }
      return {
        product_id: product.id,
        product_name: product.name,
        size: item.size,
        quantity: item.quantity,
        unit_price: unitPrice,
        total_price: unitPrice * item.quantity,
        image_url: getProductImage(product)
      };
    });

    const totalQuantity = pricedItems.reduce((sum, item) => sum + item.quantity, 0);
    const subtotal = pricedItems.reduce((sum, item) => sum + item.total_price, 0);
    // Matches the existing XML storefront's 2-piece / 3-piece offer.
    const discount = totalQuantity === 2 ? 100 : (totalQuantity >= 3 ? 250 : 0);

    const { data: deliverySettings, error: deliveryError } = await supabase
      .from('delivery_settings')
      .select('inside_dhaka_charge, outside_dhaka_charge, free_delivery_min_quantity')
      .eq('id', 1)
      .maybeSingle();

    if (deliveryError) return sendDatabaseError(res, 'ডেলিভারি চার্জ পাওয়া যায়নি।', deliveryError);

    const settings = deliverySettings || {};
    let deliveryCharge = isDhakaDistrict(shippingDistrict)
      ? Number(settings.inside_dhaka_charge ?? 60)
      : Number(settings.outside_dhaka_charge ?? 120);
    const freeDeliveryMinimum = Number(settings.free_delivery_min_quantity ?? 3);
    if (totalQuantity >= freeDeliveryMinimum) deliveryCharge = 0;
    const grandTotal = Math.max(0, subtotal - discount + deliveryCharge);

    // Find or create the customer by unique phone number.
    let { data: customer, error: customerLookupError } = await supabase
      .from('customers')
      .select('id, total_orders, total_spent')
      .eq('customer_phone', customerPhone)
      .maybeSingle();

    if (customerLookupError) return sendDatabaseError(res, 'কাস্টমারের তথ্য যাচাই করা যায়নি।', customerLookupError);

    if (customer) {
      const { error: customerUpdateError } = await supabase
        .from('customers')
        .update({ customer_name: customerName })
        .eq('id', customer.id);
      if (customerUpdateError) return sendDatabaseError(res, 'কাস্টমারের তথ্য আপডেট করা যায়নি।', customerUpdateError);
    } else {
      const { data: newCustomer, error: customerInsertError } = await supabase
        .from('customers')
        .insert({ customer_name: customerName, customer_phone: customerPhone })
        .select('id, total_orders, total_spent')
        .single();

      if (customerInsertError) {
        // If two first orders arrive together, re-read the unique phone record.
        if (customerInsertError.code === '23505') {
          const retry = await supabase.from('customers')
            .select('id, total_orders, total_spent')
            .eq('customer_phone', customerPhone)
            .single();
          if (retry.error) return sendDatabaseError(res, 'কাস্টমারের তথ্য পাওয়া যায়নি।', retry.error);
          customer = retry.data;
        } else {
          return sendDatabaseError(res, 'কাস্টমারের তথ্য তৈরি করা যায়নি।', customerInsertError);
        }
      } else {
        customer = newCustomer;
      }
    }

    const orderPayload = {
      client_request_id: clientRequestId,
      customer_id: customer.id,
      customer_name: customerName,
      customer_phone: customerPhone,
      shipping_district: shippingDistrict,
      shipping_address: shippingAddress,
      subtotal,
      discount,
      delivery_charge: deliveryCharge,
      grand_total: grandTotal,
      payment_method: 'cash_on_delivery',
      payment_status: 'unpaid',
      order_status: 'pending'
    };

    const { data: order, error: orderError } = await supabase
      .from('orders')
      .insert(orderPayload)
      .select('id, order_number, grand_total')
      .single();

    if (orderError) {
      if (orderError.code === '23505' && clientRequestId) {
        const retry = await supabase.from('orders')
          .select('order_number, grand_total')
          .eq('client_request_id', clientRequestId)
          .maybeSingle();
        if (!retry.error && retry.data) {
          return res.json({
            success: true,
            duplicate: true,
            order_number: retry.data.order_number,
            grand_total: Number(retry.data.grand_total)
          });
        }
      }
      return sendDatabaseError(res, 'অর্ডার তৈরি করা যায়নি।', orderError);
    }

    const orderItems = pricedItems.map((item) => ({ ...item, order_id: order.id }));
    const { error: itemsError } = await supabase.from('order_items').insert(orderItems);
    if (itemsError) {
      // Best-effort rollback so the database does not keep an order without items.
      const rollback = await supabase.from('orders').delete().eq('id', order.id);
      if (rollback.error) console.error('Order rollback failed:', rollback.error.message);
      return sendDatabaseError(res, 'অর্ডারের পণ্য সংরক্ষণ করা যায়নি।', itemsError);
    }

    const nextOrderCount = Number(customer.total_orders || 0) + 1;
    const nextTotalSpent = Number(customer.total_spent || 0) + grandTotal;
    const { error: customerTotalsError } = await supabase
      .from('customers')
      .update({ total_orders: nextOrderCount, total_spent: nextTotalSpent })
      .eq('id', customer.id);

    if (customerTotalsError) {
      // The order is already saved; log this secondary summary issue only.
      console.error('Customer totals update failed:', customerTotalsError.message);
    }

    return res.status(201).json({
      success: true,
      order_number: order.order_number,
      grand_total: Number(order.grand_total),
      subtotal,
      discount,
      delivery_charge: deliveryCharge
    });
  } catch (error) {
    console.error('Checkout error:', error?.message || error);
    return res.status(500).json({ success: false, error: 'অর্ডার প্রসেস করতে সার্ভারে সমস্যা হয়েছে।' });
  }
});

// -----------------------------------------------------------------------------
// ADMIN: LIST ORDERS (Requires Supabase Auth + admin_profiles permission)
// -----------------------------------------------------------------------------
app.get('/api/admin/orders', requireAdmin, async (req, res) => {
  const page = Math.max(1, Number.parseInt(req.query.page, 10) || 1);
  const pageSize = Math.min(100, Math.max(1, Number.parseInt(req.query.limit, 10) || 25));
  const from = (page - 1) * pageSize;
  const to = from + pageSize - 1;

  try {
    const { data, error, count } = await supabase
      .from('orders')
      .select('*, order_items(*)', { count: 'exact' })
      .order('created_at', { ascending: false })
      .range(from, to);

    if (error) return sendDatabaseError(res, 'অর্ডারের তালিকা লোড করা যায়নি।', error);
    return res.json({ success: true, page, limit: pageSize, total: count || 0, orders: data || [] });
  } catch (error) {
    return sendDatabaseError(res, 'অর্ডারের তালিকা লোড করা যায়নি।', error);
  }
});

// ADMIN: UPDATE ORDER STATUS
app.patch('/api/admin/orders/:id/status', requireAdmin, async (req, res) => {
  const orderId = cleanText(req.params.id, 80);
  const orderStatus = cleanText(req.body?.order_status, 30).toLowerCase();
  const allowedStatuses = ['pending', 'confirmed', 'processing', 'shipped', 'delivered', 'cancelled'];

  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(orderId)) {
    return res.status(400).json({ success: false, error: 'Invalid order ID.' });
  }
  if (!allowedStatuses.includes(orderStatus)) {
    return res.status(400).json({ success: false, error: 'Invalid order status.' });
  }

  try {
    const { data, error } = await supabase
      .from('orders')
      .update({ order_status: orderStatus })
      .eq('id', orderId)
      .select('id, order_number, order_status')
      .maybeSingle();

    if (error) return sendDatabaseError(res, 'অর্ডারের Status আপডেট করা যায়নি।', error);
    if (!data) return res.status(404).json({ success: false, error: 'Order not found.' });
    return res.json({ success: true, order: data });
  } catch (error) {
    return sendDatabaseError(res, 'অর্ডারের Status আপডেট করা যায়নি।', error);
  }
});

// -----------------------------------------------------------------------------
// NOT FOUND / ERROR HANDLERS
// -----------------------------------------------------------------------------
app.use((req, res) => {
  res.status(404).json({ success: false, error: 'API endpoint not found.' });
});

app.use((error, req, res, next) => {
  if (res.headersSent) return next(error);
  if (error instanceof SyntaxError && error.status === 400 && 'body' in error) {
    return res.status(400).json({ success: false, error: 'Invalid JSON request body.' });
  }
  console.error('Unhandled API error:', error?.message || error);
  return res.status(500).json({ success: false, error: 'Internal server error.' });
});

// -----------------------------------------------------------------------------
// START SERVER
// -----------------------------------------------------------------------------
if (require.main === module) {
  app.listen(PORT, () => {
    console.log(`ForLax Fashion API running on port ${PORT}`);
  });
}

module.exports = app;
