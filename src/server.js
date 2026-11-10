
'use strict';

require('dotenv').config();

const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const { createClient } = require('@supabase/supabase-js');

const app = express();
const PORT = Number(process.env.PORT) || 3000;

// ENVIRONMENT / DATABASE
const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_SERVICE_ROLE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY;
const SUPABASE_ANON_KEY = process.env.SUPABASE_ANON_KEY;
const configuredOrigins = (process.env.CORS_ORIGIN || '*')
  .split(',')
  .map(value => value.trim())
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

// Separate client for admin email/password login

const authClient = SUPABASE_URL && SUPABASE_ANON_KEY
  ? createClient(SUPABASE_URL, SUPABASE_ANON_KEY, {
      auth: {
        autoRefreshToken: false,
        persistSession: false,
        detectSessionInUrl: false
      }
    })
  : null;

// MIDDLEWARE
app.set('trust proxy', 1);
app.use(helmet());

app.use(cors({
  origin(origin, callback) {
    if (
      !origin ||
      configuredOrigins.includes('*') ||
      configuredOrigins.includes(origin)
    ) {
      return callback(null, true);
    }

    return callback(
      new Error('This website origin is not allowed by CORS.')
    );
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

// HELPERS
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

  let phone = String(value ?? '').replace(
    /[০-৯]/g,
    digit => String(banglaDigits.indexOf(digit))
  );

  phone = phone.replace(/\D/g, '');

  if (phone.startsWith('880') && phone.length === 13) {
    phone = `0${phone.slice(3)}`;
  } else if (phone.startsWith('88') && phone.length === 13) {
    phone = phone.slice(2);
  }

  return phone;
}

function isDhakaDistrict(value) {
  const district = cleanText(value, 100).toLowerCase();

  return (
    district === 'dhaka' ||
    district.includes('ঢাকার ভিতরে') ||
    district.includes('inside dhaka')
  );
}

function getBaseProductName(productName, size) {
  let name = cleanText(productName, 250);
  const selectedSize = cleanText(size, 30);

  if (selectedSize) {
    const escaped = selectedSize.replace(
      /[.*+?^${}()|[\]\\]/g,
      '\\$&'
    );

    name = name.replace(
      new RegExp(`\\s*\\(${escaped}\\)\\s*$`, 'i'),
      ''
    ).trim();
  }

  return name.replace(/\s*\((M|L|XL|XXL)\)\s*$/i, '').trim();
}

function getProductImage(product) {
  if (product.image) return product.image;

  if (Array.isArray(product.images) && product.images.length > 0) {
    const first = product.images[0];

    return typeof first === 'string'
      ? first
      : (first?.url || first?.image_url || null);
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

// AUTHENTICATION
function getBearerToken(req) {
  const header = cleanText(req.headers.authorization, 2000);
  const match = header.match(/^Bearer\s+(.+)$/i);

  return match ? match[1] : null;
}

async function requireAdmin(req, res, next) {
  if (!requireDatabase(res)) return;

  const token = getBearerToken(req);

  if (!token) {
    return res.status(401).json({
      success: false,
      error: 'Admin login required.'
    });
  }

  try {
    const { data: authData, error: authError } =
      await supabase.auth.getUser(token);

    if (authError || !authData?.user) {
      return res.status(401).json({
        success: false,
        error: 'Admin session is invalid or expired.'
      });
    }

    const { data: profile, error: profileError } = await supabase
      .from('admin_profiles')
      .select('role, is_active')
      .eq('user_id', authData.user.id)
      .maybeSingle();

    if (profileError) {
      return sendDatabaseError(
        res,
        'Could not verify admin permission.',
        profileError
      );
    }

    if (
      !profile ||
      profile.is_active !== true ||
      !['admin', 'owner', 'super_admin'].includes(profile.role)
    ) {
      return res.status(403).json({
        success: false,
        error: 'This account does not have admin permission.'
      });
    }

    req.adminUser = authData.user;
    req.adminProfile = profile;

    return next();

  } catch (error) {
    console.error(
      'Admin authorization error:',
      error?.message || error
    );

    return res.status(401).json({
      success: false,
      error: 'Could not verify admin session.'
    });
  }
}

// -----------------------------------------------------------------------------
// ADMIN LOGIN API
// -----------------------------------------------------------------------------

app.post('/api/admin/login', async (req, res) => {

  if (!authClient || !supabase) {
    return res.status(503).json({
      success: false,
      error: 'Supabase configuration missing.'
    });
  }

  const email = cleanText(req.body?.email, 254).toLowerCase();
  const password = String(req.body?.password || '');

  if (!email || !password) {
    return res.status(400).json({
      success: false,
      error: 'ইমেইল ও পাসওয়ার্ড দিতে হবে।'
    });
  }

  try {
    // Supabase email/password authentication
    const { data, error } =
      await authClient.auth.signInWithPassword({
        email,
        password
      });

    if (error || !data?.user || !data?.session) {
      return res.status(401).json({
        success: false,
        error: 'ইমেইল অথবা পাসওয়ার্ড সঠিক নয়।'
      });
    }

    // Verify admin profile
    const { data: profile, error: profileError } = await supabase
      .from('admin_profiles')
      .select('role, is_active')
      .eq('user_id', data.user.id)
      .maybeSingle();

    if (profileError) {
      console.error('Admin profile error:', profileError.message);

      return res.status(500).json({
        success: false,
        error: 'Admin permission যাচাই করা যায়নি।'
      });
    }

    if (
      !profile ||
      profile.is_active !== true ||
      !['admin', 'owner', 'super_admin'].includes(profile.role)
    ) {
      return res.status(403).json({
        success: false,
        error: 'এই অ্যাকাউন্টের Admin permission নেই।'
      });
    }

    // Successful login response
    return res.json({
      success: true,
      message: 'Login successful.',

      user: {
        id: data.user.id,
        email: data.user.email || null
      },

      profile: {
        role: profile.role,
        is_active: profile.is_active
      },

      session: {
        access_token: data.session.access_token,
        refresh_token: data.session.refresh_token,
        expires_at: data.session.expires_at,
        expires_in: data.session.expires_in,
        token_type: data.session.token_type
      }
    });

  } catch (error) {
    console.error(
      'Admin login error:',
      error?.message || error
    );

    return res.status(500).json({
      success: false,
      error: 'Login করার সময় সার্ভারে সমস্যা হয়েছে।'
    });
  }

});


// -----------------------------------------------------------------------------
// ADMIN: CURRENT AUTHENTICATED PROFILE
// -----------------------------------------------------------------------------

app.get('/api/admin/me', requireAdmin, (req, res) => {
  return res.json({
    success: true,
    user: {
      id: req.adminUser.id,
      email: req.adminUser.email || null
    },
    profile: {
      role: req.adminProfile.role,
      is_active: req.adminProfile.is_active
    }
  });
});


// -----------------------------------------------------------------------------
// ADMIN: RECENT ORDERS FOR LIVE NOTIFICATIONS
// -----------------------------------------------------------------------------

app.get('/api/admin/poll-new-orders', requireAdmin, async (req, res) => {
  try {
    // Return a short rolling window; the panel deduplicates notifications by order ID.
    const since = new Date(Date.now() - 2 * 60 * 1000).toISOString();

    const { data, error } = await supabase
      .from('orders')
      .select('id, order_number, customer_name, grand_total, created_at')
      .gte('created_at', since)
      .order('created_at', { ascending: false })
      .limit(50);

    if (error) {
      return sendDatabaseError(
        res,
        'নতুন অর্ডার চেক করা যায়নি।',
        error
      );
    }

    return res.json({
      success: true,
      new_orders: data || []
    });

  } catch (error) {
    return sendDatabaseError(
      res,
      'নতুন অর্ডার চেক করা যায়নি।',
      error
    );
  }
});


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
      console.error(
        'Health check database error:',
        error.message
      );

      return res.status(503).json({
        success: false,
        server: 'online',
        database: 'error'
      });
    }

    return res.json({
      success: true,
      server: 'online',
      database: 'connected',
      timestamp: new Date().toISOString()
    });

  } catch (error) {
    console.error(
      'Health check failed:',
      error?.message || error
    );

    return res.status(503).json({
      success: false,
      server: 'online',
      database: 'error'
    });
  }
});


// -----------------------------------------------------------------------------
// STOREFRONT DATA
// -----------------------------------------------------------------------------

app.get('/api/store-data', async (req, res) => {
  if (!requireDatabase(res)) return;

  try {
    const [
      contentResult,
      productsResult,
      deliveryResult
    ] = await Promise.all([
      supabase
        .from('site_content')
        .select('content_key, content_value'),

      supabase
        .from('products')
        .select(`
          id,
          product_code,
          category_id,
          name,
          description,
          regular_price,
          price,
          image,
          images,
          sizes,
          colors,
          stock,
          is_active,
          sort_order
        `)
        .eq('is_active', true)
        .order('sort_order', { ascending: true })
        .order('created_at', { ascending: false }),

      supabase
        .from('delivery_settings')
        .select(`
          inside_dhaka_charge,
          outside_dhaka_charge,
          free_delivery_min_quantity
        `)
        .eq('id', 1)
        .maybeSingle()
    ]);

    if (contentResult.error) {
      return sendDatabaseError(
        res,
        'ওয়েবসাইটের সেটিংস লোড করা যায়নি।',
        contentResult.error
      );
    }

    if (productsResult.error) {
      return sendDatabaseError(
        res,
        'পণ্যের তালিকা লোড করা যায়নি।',
        productsResult.error
      );
    }

    if (deliveryResult.error) {
      return sendDatabaseError(
        res,
        'ডেলিভারি সেটিংস লোড করা যায়নি।',
        deliveryResult.error
      );
    }

    const content = {};

    for (const row of contentResult.data || []) {
      content[row.content_key] = row.content_value;
    }

    const delivery = deliveryResult.data || {};

    if (content.del_inside_charge === undefined) {
      content.del_inside_charge =
        Number(delivery.inside_dhaka_charge ?? 60);
    }

    if (content.del_outside_charge === undefined) {
      content.del_outside_charge =
        Number(delivery.outside_dhaka_charge ?? 120);
    }

    const products = (productsResult.data || []).map(product => ({
      ...product,
      image: getProductImage(product) || '',
      size: ''
    }));

    return res.json({
      success: true,
      content,
      products
    });

  } catch (error) {
    return sendDatabaseError(
      res,
      'Store data load failed.',
      error
    );
  }
});

// -----------------------------------------------------------------------------
// INCOMPLETE ORDER LEAD
// -----------------------------------------------------------------------------

app.post('/api/incomplete-order', async (req, res) => {
  if (!requireDatabase(res)) return;

  const customerName = cleanText(req.body?.customer_name, 150);
  const customerPhone = normalizePhone(req.body?.customer_phone);
  const shippingDistrict = cleanText(req.body?.shipping_district, 100);
  const shippingAddress = cleanText(req.body?.shipping_address, 1000);

  if (customerPhone.length !== 11) {
    return res.status(400).json({
      success: false,
      error: 'সঠিক ১১ ডিজিটের মোবাইল নম্বর প্রয়োজন।'
    });
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

    if (error) {
      return sendDatabaseError(
        res,
        'অসম্পূর্ণ অর্ডার সংরক্ষণ করা যায়নি।',
        error
      );
    }

    return res.status(201).json({
      success: true,
      lead_id: data.id
    });

  } catch (error) {
    return sendDatabaseError(
      res,
      'অসম্পূর্ণ অর্ডার সংরক্ষণ করা যায়নি।',
      error
    );
  }
});


// -----------------------------------------------------------------------------
// CUSTOMER CHECKOUT
// -----------------------------------------------------------------------------

app.post('/api/checkout', async (req, res) => {
  if (!requireDatabase(res)) return;

  const customerName = cleanText(req.body?.customer_name, 150);
  const customerPhone = normalizePhone(req.body?.customer_phone);
  const shippingDistrict = cleanText(req.body?.shipping_district, 100);
  const shippingAddress = cleanText(req.body?.shipping_address, 1000);
  const clientRequestId =
    cleanText(req.body?.client_request_id, 120) || null;

  const requestedItems = Array.isArray(req.body?.items)
    ? req.body.items
    : [];

  // VALIDATION

  if (!customerName) {
    return res.status(400).json({
      success: false,
      error: 'কাস্টমারের নাম প্রয়োজন।'
    });
  }

  if (customerPhone.length !== 11) {
    return res.status(400).json({
      success: false,
      error: 'সঠিক ১১ ডিজিটের মোবাইল নম্বর প্রয়োজন।'
    });
  }

  if (!shippingDistrict || !shippingAddress) {
    return res.status(400).json({
      success: false,
      error: 'ডেলিভারি এলাকা ও সম্পূর্ণ ঠিকানা প্রয়োজন।'
    });
  }

  if (requestedItems.length < 1 || requestedItems.length > 30) {
    return res.status(400).json({
      success: false,
      error: '১ থেকে ৩০টি পণ্য নির্বাচন করুন।'
    });
  }

  try {

    // PREVENT DUPLICATE ORDER

    if (clientRequestId) {
      const {
        data: existingOrder,
        error: existingError
      } = await supabase
        .from('orders')
        .select('order_number, grand_total')
        .eq('client_request_id', clientRequestId)
        .maybeSingle();

      if (existingError) {
        return sendDatabaseError(
          res,
          'আগের অর্ডার যাচাই করা যায়নি।',
          existingError
        );
      }

      if (existingOrder) {
        return res.json({
          success: true,
          duplicate: true,
          order_number: existingOrder.order_number,
          grand_total: Number(existingOrder.grand_total)
        });
      }
    }


    // VALIDATE PRODUCTS AND QUANTITIES

    const normalizedItems = [];

    for (const item of requestedItems) {
      const quantity = Number(item?.quantity);
      const size = cleanText(item?.size, 30) || 'Standard';

      const productName = getBaseProductName(
        item?.product_name,
        size
      );

      if (
        !productName ||
        !Number.isInteger(quantity) ||
        quantity < 1 ||
        quantity > 50
      ) {
        return res.status(400).json({
          success: false,
          error: 'একটি পণ্যের নাম, সাইজ অথবা পরিমাণ সঠিক নয়।'
        });
      }

      normalizedItems.push({
        productName,
        size,
        quantity
      });
    }


    // FETCH REAL PRODUCT PRICES FROM DATABASE

    const productNames = [
      ...new Set(normalizedItems.map(item => item.productName))
    ];

    const {
      data: products,
      error: productsError
    } = await supabase
      .from('products')
      .select('id, name, price, image, images, is_active')
      .in('name', productNames)
      .eq('is_active', true);

    if (productsError) {
      return sendDatabaseError(
        res,
        'পণ্যের দাম যাচাই করা যায়নি।',
        productsError
      );
    }

    const productMap = new Map();

    for (const product of products || []) {
      if (productMap.has(product.name)) {
        return res.status(409).json({
          success: false,
          error: `একই নামে একাধিক পণ্য আছে: ${product.name}`
        });
      }

      productMap.set(product.name, product);
    }

    const missingProduct = productNames.find(
      name => !productMap.has(name)
    );

    if (missingProduct) {
      return res.status(409).json({
        success: false,
        error:
          `পণ্যটি Products তালিকায় পাওয়া যায়নি: ${missingProduct}।`
      });
    }


    // CALCULATE PRODUCT PRICES

    const pricedItems = normalizedItems.map(item => {
      const product = productMap.get(item.productName);
      const unitPrice = Number(product.price);

      if (!Number.isFinite(unitPrice) || unitPrice < 0) {
        throw new Error(
          `Invalid database price for ${item.productName}`
        );
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


    // SUBTOTAL AND DISCOUNT

    const totalQuantity = pricedItems.reduce(
      (sum, item) => sum + item.quantity,
      0
    );

    const subtotal = pricedItems.reduce(
      (sum, item) => sum + item.total_price,
      0
    );

    // Existing storefront offer:
    // 2 pieces = 100 BDT discount
    // 3 or more pieces = 250 BDT discount

    const discount = totalQuantity === 2
      ? 100
      : totalQuantity >= 3
        ? 250
        : 0;


    // DELIVERY SETTINGS

    const {
      data: deliverySettings,
      error: deliveryError
    } = await supabase
      .from('delivery_settings')
      .select(`
        inside_dhaka_charge,
        outside_dhaka_charge,
        free_delivery_min_quantity
      `)
      .eq('id', 1)
      .maybeSingle();

    if (deliveryError) {
      return sendDatabaseError(
        res,
        'ডেলিভারি চার্জ পাওয়া যায়নি।',
        deliveryError
      );
    }

    const settings = deliverySettings || {};

    let deliveryCharge = isDhakaDistrict(shippingDistrict)
      ? Number(settings.inside_dhaka_charge ?? 60)
      : Number(settings.outside_dhaka_charge ?? 120);

    const freeDeliveryMinimum = Number(
      settings.free_delivery_min_quantity ?? 3
    );

    if (totalQuantity >= freeDeliveryMinimum) {
      deliveryCharge = 0;
    }

    const grandTotal = Math.max(
      0,
      subtotal - discount + deliveryCharge
    );


    // FIND OR CREATE CUSTOMER

    let {
      data: customer,
      error: customerLookupError
    } = await supabase
      .from('customers')
      .select('id, total_orders, total_spent')
      .eq('customer_phone', customerPhone)
      .maybeSingle();

    if (customerLookupError) {
      return sendDatabaseError(
        res,
        'কাস্টমারের তথ্য যাচাই করা যায়নি।',
        customerLookupError
      );
    }

    if (customer) {
      const { error: customerUpdateError } = await supabase
        .from('customers')
        .update({
          customer_name: customerName
        })
        .eq('id', customer.id);

      if (customerUpdateError) {
        return sendDatabaseError(
          res,
          'কাস্টমারের তথ্য আপডেট করা যায়নি।',
          customerUpdateError
        );
      }

    } else {
      const {
        data: newCustomer,
        error: customerInsertError
      } = await supabase
        .from('customers')
        .insert({
          customer_name: customerName,
          customer_phone: customerPhone
        })
        .select('id, total_orders, total_spent')
        .single();

      if (customerInsertError) {
        if (customerInsertError.code === '23505') {
          const retry = await supabase
            .from('customers')
            .select('id, total_orders, total_spent')
            .eq('customer_phone', customerPhone)
            .single();

          if (retry.error) {
            return sendDatabaseError(
              res,
              'কাস্টমারের তথ্য পাওয়া যায়নি।',
              retry.error
            );
          }

          customer = retry.data;

        } else {
          return sendDatabaseError(
            res,
            'কাস্টমারের তথ্য তৈরি করা যায়নি।',
            customerInsertError
          );
        }

      } else {
        customer = newCustomer;
      }
    }


    // CREATE ORDER

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

    const {
      data: order,
      error: orderError
    } = await supabase
      .from('orders')
      .insert(orderPayload)
      .select('id, order_number, grand_total')
      .single();

    if (orderError) {
      if (orderError.code === '23505' && clientRequestId) {
        const retry = await supabase
          .from('orders')
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

      return sendDatabaseError(
        res,
        'অর্ডার তৈরি করা যায়নি।',
        orderError
      );
    }


    // SAVE ORDER ITEMS

    const orderItems = pricedItems.map(item => ({
      ...item,
      order_id: order.id
    }));

    const { error: itemsError } = await supabase
      .from('order_items')
      .insert(orderItems);

    if (itemsError) {
      const rollback = await supabase
        .from('orders')
        .delete()
        .eq('id', order.id);

      if (rollback.error) {
        console.error(
          'Order rollback failed:',
          rollback.error.message
        );
      }

      return sendDatabaseError(
        res,
        'অর্ডারের পণ্য সংরক্ষণ করা যায়নি।',
        itemsError
      );
    }


    // UPDATE CUSTOMER SUMMARY

    const nextOrderCount =
      Number(customer.total_orders || 0) + 1;

    const nextTotalSpent =
      Number(customer.total_spent || 0) + grandTotal;

    const { error: customerTotalsError } = await supabase
      .from('customers')
      .update({
        total_orders: nextOrderCount,
        total_spent: nextTotalSpent
      })
      .eq('id', customer.id);

    if (customerTotalsError) {
      console.error(
        'Customer totals update failed:',
        customerTotalsError.message
      );
    }


    // SUCCESS RESPONSE

    return res.status(201).json({
      success: true,
      order_number: order.order_number,
      grand_total: Number(order.grand_total),
      subtotal,
      discount,
      delivery_charge: deliveryCharge
    });

  } catch (error) {
    console.error(
      'Checkout error:',
      error?.message || error
    );

    return res.status(500).json({
      success: false,
      error: 'অর্ডার প্রসেস করতে সার্ভারে সমস্যা হয়েছে।'
    });
  }
});

// -----------------------------------------------------------------------------
// ADMIN: DASHBOARD METRICS
// -----------------------------------------------------------------------------

app.get('/api/admin/metrics', requireAdmin, async (req, res) => {
  try {
    const { data: orders, error } = await supabase
      .from('orders')
      .select('order_status, grand_total');

    if (error) {
      return sendDatabaseError(
        res,
        'Dashboard metrics লোড করা যায়নি।',
        error
      );
    }

    const metrics = {
      total: orders.length,
      new: 0,
      pending: 0,
      confirmed: 0,
      processing: 0,
      shipped: 0,
      delivered: 0,
      cancelled: 0,
      revenue: 0
    };

    for (const order of orders) {
      const status = String(order.order_status || 'pending')
        .toLowerCase();

      if (
        Object.prototype.hasOwnProperty.call(metrics, status)
      ) {
        metrics[status]++;
      }

      if (status !== 'cancelled') {
        metrics.revenue += Number(order.grand_total || 0);
      }
    }

    return res.json({
      success: true,
      ...metrics
    });

  } catch (error) {
    return sendDatabaseError(
      res,
      'Dashboard metrics লোড করা যায়নি।',
      error
    );
  }
});


// -----------------------------------------------------------------------------
// ADMIN: LIST ORDERS WITH PAGINATION AND STATUS FILTER
// -----------------------------------------------------------------------------

app.get('/api/admin/orders', requireAdmin, async (req, res) => {
  const page = Math.max(
    1,
    Number.parseInt(req.query.page, 10) || 1
  );

  const pageSize = Math.min(
    100,
    Math.max(1, Number.parseInt(req.query.limit, 10) || 100)
  );

  const from = (page - 1) * pageSize;
  const to = from + pageSize - 1;

  const requestedStatus = cleanText(
    req.query.status,
    30
  ).toLowerCase();

  const allowedStatuses = [
    'new',
    'pending',
    'confirmed',
    'processing',
    'shipped',
    'delivered',
    'cancelled'
  ];

  try {
    let query = supabase
      .from('orders')
      .select('*, order_items(*)', { count: 'exact' })
      .order('created_at', { ascending: false });

    if (
      requestedStatus &&
      requestedStatus !== 'all' &&
      allowedStatuses.includes(requestedStatus)
    ) {
      query = query.eq('order_status', requestedStatus);
    }

    const { data, error, count } = await query.range(from, to);

    if (error) {
      return sendDatabaseError(
        res,
        'অর্ডারের তালিকা লোড করা যায়নি।',
        error
      );
    }

    return res.json({
      success: true,
      orders: data || [],
      pagination: {
        page,
        limit: pageSize,
        total: count || 0,
        total_pages: Math.ceil((count || 0) / pageSize)
      }
    });

  } catch (error) {
    return sendDatabaseError(
      res,
      'অর্ডারের তালিকা লোড করা যায়নি।',
      error
    );
  }
});


// -----------------------------------------------------------------------------
// ADMIN: UPDATE SINGLE ORDER STATUS
// -----------------------------------------------------------------------------

app.patch('/api/admin/orders/:id/status', requireAdmin, async (req, res) => {
  const orderId = cleanText(req.params.id, 80);

  const orderStatus = cleanText(
    req.body?.order_status || req.body?.status,
    30
  ).toLowerCase();

  const allowedStatuses = [
    'pending',
    'confirmed',
    'processing',
    'shipped',
    'delivered',
    'cancelled'
  ];

  if (
    !/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i
      .test(orderId)
  ) {
    return res.status(400).json({
      success: false,
      error: 'Invalid order ID.'
    });
  }

  if (!allowedStatuses.includes(orderStatus)) {
    return res.status(400).json({
      success: false,
      error: 'Invalid order status.'
    });
  }

  try {
    const { data, error } = await supabase
      .from('orders')
      .update({
        order_status: orderStatus
      })
      .eq('id', orderId)
      .select('id, order_number, order_status')
      .maybeSingle();

    if (error) {
      return sendDatabaseError(
        res,
        'অর্ডারের Status আপডেট করা যায়নি।',
        error
      );
    }

    if (!data) {
      return res.status(404).json({
        success: false,
        error: 'Order not found.'
      });
    }

    return res.json({
      success: true,
      order: data
    });

  } catch (error) {
    return sendDatabaseError(
      res,
      'অর্ডারের Status আপডেট করা যায়নি।',
      error
    );
  }
});


// -----------------------------------------------------------------------------
// BACKWARD-COMPATIBLE STATUS UPDATE
// -----------------------------------------------------------------------------

app.post('/api/admin/orders/update-status', requireAdmin, async (req, res) => {
  const orderId = cleanText(req.body?.order_id, 80);
  const status = cleanText(req.body?.status, 30).toLowerCase();

  const allowedStatuses = [
    'pending',
    'confirmed',
    'processing',
    'shipped',
    'delivered',
    'cancelled'
  ];

  if (!orderId || !allowedStatuses.includes(status)) {
    return res.status(400).json({
      success: false,
      error: 'অর্ডার ID অথবা Status সঠিক নয়।'
    });
  }

  try {
    const { data, error } = await supabase
      .from('orders')
      .update({
        order_status: status
      })
      .eq('id', orderId)
      .select('id, order_number, order_status')
      .maybeSingle();

    if (error) {
      return sendDatabaseError(
        res,
        'অর্ডারের Status আপডেট করা যায়নি।',
        error
      );
    }

    if (!data) {
      return res.status(404).json({
        success: false,
        error: 'Order not found.'
      });
    }

    return res.json({
      success: true,
      order: data
    });

  } catch (error) {
    return sendDatabaseError(
      res,
      'অর্ডারের Status আপডেট করা যায়নি।',
      error
    );
  }
});


// -----------------------------------------------------------------------------
// ADMIN: BULK UPDATE ORDER STATUS
// -----------------------------------------------------------------------------

app.post('/api/admin/orders/bulk-status', requireAdmin, async (req, res) => {
  const orderIds = Array.isArray(req.body?.order_ids)
    ? [...new Set(req.body.order_ids)]
    : [];

  const status = cleanText(
    req.body?.status,
    30
  ).toLowerCase();

  const allowedStatuses = [
    'pending',
    'confirmed',
    'processing',
    'shipped',
    'delivered',
    'cancelled'
  ];

  const validIds = orderIds.every(id =>
    /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i
      .test(String(id))
  );

  if (
    orderIds.length < 1 ||
    orderIds.length > 100 ||
    !validIds
  ) {
    return res.status(400).json({
      success: false,
      error: 'সঠিক Order ID নির্বাচন করুন।'
    });
  }

  if (!allowedStatuses.includes(status)) {
    return res.status(400).json({
      success: false,
      error: 'Invalid order status.'
    });
  }

  try {
    const { data, error } = await supabase
      .from('orders')
      .update({
        order_status: status
      })
      .in('id', orderIds)
      .select('id');

    if (error) {
      return sendDatabaseError(
        res,
        'Bulk status update ব্যর্থ হয়েছে।',
        error
      );
    }

    return res.json({
      success: true,
      updated: data?.length || 0
    });

  } catch (error) {
    return sendDatabaseError(
      res,
      'Bulk status update ব্যর্থ হয়েছে।',
      error
    );
  }
});

// -----------------------------------------------------------------------------
// ADMIN: CMS UPDATE SINGLE FIELD
// -----------------------------------------------------------------------------

app.post('/api/admin/cms/update-single', requireAdmin, async (req, res) => {
  const field = cleanText(req.body?.field, 150);
  const value = req.body?.value;

  if (!field || value === undefined) {
    return res.status(400).json({
      success: false,
      error: 'CMS field ও value প্রয়োজন।'
    });
  }

  try {
    const { data, error } = await supabase
      .from('site_content')
      .upsert(
        {
          content_key: field,
          content_value: value
        },
        {
          onConflict: 'content_key'
        }
      )
      .select()
      .single();

    if (error) {
      return sendDatabaseError(
        res,
        'CMS আপডেট করা যায়নি।',
        error
      );
    }

    return res.json({
      success: true,
      content: data
    });

  } catch (error) {
    return sendDatabaseError(
      res,
      'CMS update failed.',
      error
    );
  }
});


// -----------------------------------------------------------------------------
// ADMIN: UPDATE COMPLETE ORDER
// -----------------------------------------------------------------------------

app.post('/api/admin/orders/update', requireAdmin, async (req, res) => {
  const orderId = cleanText(req.body?.order_id, 80);

  const customerName = cleanText(
    req.body?.customer_name,
    150
  );

  const customerPhone = normalizePhone(
    req.body?.customer_phone
  );

  const shippingDistrict = cleanText(
    req.body?.shipping_district,
    100
  );

  const shippingAddress = cleanText(
    req.body?.shipping_address,
    1000
  );

  const grandTotal = Number(req.body?.grand_total);

  const orderStatus = cleanText(
    req.body?.order_status || req.body?.status,
    30
  ).toLowerCase();

  const allowedStatuses = [
    'pending',
    'confirmed',
    'processing',
    'shipped',
    'delivered',
    'cancelled'
  ];

  if (
    !orderId ||
    !customerName ||
    customerPhone.length !== 11 ||
    !shippingAddress ||
    !Number.isFinite(grandTotal) ||
    grandTotal < 0 ||
    !allowedStatuses.includes(orderStatus)
  ) {
    return res.status(400).json({
      success: false,
      error: 'অর্ডারের তথ্য সঠিকভাবে পূরণ করুন।'
    });
  }

  try {
    const { data, error } = await supabase
      .from('orders')
      .update({
        customer_name: customerName,
        customer_phone: customerPhone,
        shipping_district: shippingDistrict,
        shipping_address: shippingAddress,
        grand_total: grandTotal,
        order_status: orderStatus
      })
      .eq('id', orderId)
      .select()
      .maybeSingle();

    if (error) {
      return sendDatabaseError(
        res,
        'অর্ডারের তথ্য আপডেট করা যায়নি।',
        error
      );
    }

    if (!data) {
      return res.status(404).json({
        success: false,
        error: 'Order not found.'
      });
    }

    return res.json({
      success: true,
      order: data
    });

  } catch (error) {
    return sendDatabaseError(
      res,
      'অর্ডার আপডেট করা যায়নি।',
      error
    );
  }
});


// -----------------------------------------------------------------------------
// ADMIN: DELETE ORDER
// -----------------------------------------------------------------------------

app.post('/api/admin/orders/delete', requireAdmin, async (req, res) => {
  const orderId = cleanText(req.body?.order_id, 80);

  if (
    !/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i
      .test(orderId)
  ) {
    return res.status(400).json({
      success: false,
      error: 'সঠিক Order ID প্রয়োজন।'
    });
  }

  try {
    const {
      data: order,
      error: lookupError
    } = await supabase
      .from('orders')
      .select('id')
      .eq('id', orderId)
      .maybeSingle();

    if (lookupError) {
      return sendDatabaseError(
        res,
        'Order যাচাই করা যায়নি।',
        lookupError
      );
    }

    if (!order) {
      return res.status(404).json({
        success: false,
        error: 'Order not found.'
      });
    }

    // DELETE ORDER ITEMS FIRST

    const { error: itemsError } = await supabase
      .from('order_items')
      .delete()
      .eq('order_id', orderId);

    if (itemsError) {
      return sendDatabaseError(
        res,
        'Order items মুছে ফেলা যায়নি।',
        itemsError
      );
    }

    // DELETE MAIN ORDER

    const { error: deleteError } = await supabase
      .from('orders')
      .delete()
      .eq('id', orderId);

    if (deleteError) {
      return sendDatabaseError(
        res,
        'Order মুছে ফেলা যায়নি।',
        deleteError
      );
    }

    return res.json({
      success: true,
      message: 'Order deleted successfully.'
    });

  } catch (error) {
    return sendDatabaseError(
      res,
      'Order delete failed.',
      error
    );
  }
});


// -----------------------------------------------------------------------------
// ADMIN: GOOD CUSTOMER API
// NOTE: Original database schema does not contain a good-customer flag.
// -----------------------------------------------------------------------------

app.get('/api/admin/good-customers', requireAdmin, async (req, res) => {
  return res.status(501).json({
    success: false,
    error: 'Good customer API এখনো implement করা হয়নি।'
  });
});

// -----------------------------------------------------------------------------
// 404 HANDLER
// -----------------------------------------------------------------------------

app.use((req, res) => {
  return res.status(404).json({
    success: false,
    error: 'API endpoint পাওয়া যায়নি।'
  });
});


// -----------------------------------------------------------------------------
// GLOBAL ERROR HANDLER
// -----------------------------------------------------------------------------

app.use((error, req, res, next) => {
  console.error(
    'Unhandled server error:',
    error?.message || error
  );

  if (res.headersSent) {
    return next(error);
  }

  if (
    error instanceof SyntaxError &&
    error.status === 400 &&
    'body' in error
  ) {
    return res.status(400).json({
      success: false,
      error: 'Invalid JSON request body.'
    });
  }

  return res.status(500).json({
    success: false,
    error: 'সার্ভারে একটি সমস্যা হয়েছে।'
  });
});


// -----------------------------------------------------------------------------
// START SERVER
// -----------------------------------------------------------------------------

if (require.main === module) {
  app.listen(PORT, () => {
    console.log(`ForLax API running on port ${PORT}`);
  });
}

module.exports = app;
