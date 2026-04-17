// ==================== 加解密工具函数 ====================
const encoder = new TextEncoder();
const decoder = new TextDecoder();

function bufferToHex(buffer) {
  return Array.from(new Uint8Array(buffer))
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

function hexToArrayBuffer(hex) {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.substr(i, 2), 16);
  }
  return bytes.buffer;
}

async function deriveKey(password, saltHex = null) {
  const passwordBuffer = encoder.encode(password);
  const salt = saltHex 
    ? hexToArrayBuffer(saltHex) 
    : crypto.getRandomValues(new Uint8Array(16));
  
  const keyMaterial = await crypto.subtle.importKey(
    'raw',
    passwordBuffer,
    'PBKDF2',
    false,
    ['deriveKey']
  );
  
  const key = await crypto.subtle.deriveKey(
    {
      name: 'PBKDF2',
      salt: salt,
      iterations: 100000,
      hash: 'SHA-256'
    },
    keyMaterial,
    { name: 'AES-GCM', length: 256 },
    true,
    ['encrypt', 'decrypt']
  );
  
  return { key, salt: saltHex || bufferToHex(salt) };
}

async function encryptContent(plaintext, password) {
  const { key, salt } = await deriveKey(password);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const data = encoder.encode(plaintext);
  
  const ciphertext = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: iv },
    key,
    data
  );
  
  return {
    ciphertext,
    iv: bufferToHex(iv),
    salt
  };
}

async function decryptContent(ciphertext, ivHex, saltHex, password) {
  const { key } = await deriveKey(password, saltHex);
  const iv = hexToArrayBuffer(ivHex);
  
  const plainBuffer = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: iv },
    key,
    ciphertext
  );
  
  return decoder.decode(plainBuffer);
}

// ==================== 辅助函数：安全转换 D1 BLOB ====================
function toArrayBuffer(data) {
  if (data === null || data === undefined) return null;
  if (data instanceof ArrayBuffer) return data;
  if (ArrayBuffer.isView(data)) return data.buffer;
  if (typeof data === 'string') return encoder.encode(data).buffer;
  console.warn('未知 BLOB 类型，尝试强制转换:', typeof data, data.constructor.name);
  return new Uint8Array(data).buffer;
}

// ==================== HTTP 响应辅助函数 ====================
const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, DELETE, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type'
};

function jsonResponse(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json', ...corsHeaders }
  });
}

function errorResponse(message, status = 400) {
  return jsonResponse({ error: message }, status);
}

// ==================== 业务逻辑处理函数 ====================

async function handleCreate(request, env) {
  try {
    const body = await request.json();
    const { name, content, password } = body;
    
    if (!name || typeof name !== 'string' || name.trim() === '') {
      return errorResponse('名称不能为空', 400);
    }
    if (content === undefined || content === null) {
      return errorResponse('内容不能为空', 400);
    }
    
    console.log(`创建剪贴板: ${name}, 加密: ${!!password}`);

    // 检查名称唯一性
    let existing;
    try {
      existing = await env.DB.prepare(
        'SELECT name FROM clipboards WHERE name = ?'
      ).bind(name).first();
    } catch (dbError) {
      console.error('数据库查询失败:', dbError);
      return errorResponse('数据库查询失败，请检查 D1 绑定或表结构', 500);
    }
    
    if (existing) {
      return errorResponse('名称已存在，请换一个名称', 409);
    }
    
    let encryptedContent, ivHex, saltHex;
    const hasPassword = password && password.trim() !== '';
    
    if (hasPassword) {
      const encrypted = await encryptContent(content, password);
      encryptedContent = encrypted.ciphertext;  // ArrayBuffer
      ivHex = encrypted.iv;
      saltHex = encrypted.salt;
      console.log(`加密完成，iv: ${ivHex.substring(0,8)}..., salt: ${saltHex.substring(0,8)}...`);
    } else {
      encryptedContent = encoder.encode(content).buffer;  // ArrayBuffer
      ivHex = '';
      saltHex = '';
    }
    
    console.log('准备插入 BLOB，类型:', encryptedContent.constructor.name);
    try {
      await env.DB.prepare(`
        INSERT INTO clipboards (name, content, iv, salt)
        VALUES (?, ?, ?, ?)
      `).bind(name, encryptedContent, ivHex, saltHex).run();
    } catch (dbError) {
      console.error('插入数据失败:', dbError);
      return errorResponse('保存数据失败，请检查 D1 数据库状态', 500);
    }
    
    return jsonResponse({
      success: true,
      message: '剪贴板创建成功',
      name,
      protected: hasPassword
    }, 201);
    
  } catch (e) {
    console.error('handleCreate error:', e);
    return errorResponse('请求格式错误，请提供 JSON 格式的 name、content 和 password', 400);
  }
}

async function handleGet(request, env) {
  const url = new URL(request.url);
  const name = url.searchParams.get('name');
  const password = url.searchParams.get('password') || '';
  
  if (!name) return errorResponse('缺少 name 参数', 400);
  
  console.log(`获取剪贴板: ${name}`);

  let row;
  try {
    row = await env.DB.prepare(`
      SELECT content, iv, salt FROM clipboards WHERE name = ?
    `).bind(name).first();
  } catch (dbError) {
    console.error('数据库查询失败:', dbError);
    return errorResponse('数据库查询失败', 500);
  }
  
  if (!row) return errorResponse('未找到该名称对应的剪贴板', 404);
  
  // 关键修复：将 D1 返回的 BLOB 强制转为 ArrayBuffer
  const contentBuffer = toArrayBuffer(row.content);
  if (!contentBuffer) {
    console.error('content 字段为空或无效');
    return errorResponse('内容数据损坏', 500);
  }
  
  console.log(`读取到 BLOB，大小: ${contentBuffer.byteLength} bytes, iv存在: ${!!row.iv}`);
  
  try {
    let plainContent;
    if (row.iv) {
      if (!password) return errorResponse('该剪贴板需要密码访问', 401);
      
      console.log('开始解密，iv:', row.iv.substring(0,8)+'...', 'salt:', row.salt?.substring(0,8)+'...');
      plainContent = await decryptContent(contentBuffer, row.iv, row.salt, password);
      console.log('解密成功，内容长度:', plainContent.length);
    } else {
      plainContent = decoder.decode(contentBuffer);
    }
    return jsonResponse({ name, content: plainContent, protected: !!row.iv });
  } catch (e) {
    console.error('解密或解码失败:', e.message, e.stack);
    return errorResponse('密码错误或内容已损坏', 403);
  }
}

async function handleDelete(request, env) {
  const url = new URL(request.url);
  const name = url.searchParams.get('name');
  const password = url.searchParams.get('password') || '';
  
  if (!name) return errorResponse('缺少 name 参数', 400);
  
  console.log(`删除剪贴板: ${name}`);

  // 查询记录
  let row;
  try {
    row = await env.DB.prepare(`
      SELECT iv, salt FROM clipboards WHERE name = ?
    `).bind(name).first();
  } catch (dbError) {
    console.error('数据库查询失败:', dbError);
    return errorResponse('数据库查询失败', 500);
  }
  
  if (!row) return errorResponse('未找到该名称对应的剪贴板', 404);
  
  // 加密验证
  if (row.iv) {
    if (!password) return errorResponse('该剪贴板需要密码才能删除', 401);
    
    const fullRow = await env.DB.prepare(`
      SELECT content, iv, salt FROM clipboards WHERE name = ?
    `).bind(name).first();
    
    const contentBuffer = toArrayBuffer(fullRow.content);
    if (!contentBuffer) {
      return errorResponse('内容数据损坏', 500);
    }
    
    try {
      await decryptContent(contentBuffer, fullRow.iv, fullRow.salt, password);
    } catch (e) {
      console.error('密码验证失败:', e);
      return errorResponse('密码错误，无权删除', 403);
    }
  }
  
  // 执行删除
  try {
    await env.DB.prepare(`DELETE FROM clipboards WHERE name = ?`).bind(name).run();
  } catch (dbError) {
    console.error('删除失败:', dbError);
    return errorResponse('删除失败', 500);
  }
  
  return jsonResponse({
    success: true,
    message: '剪贴板删除成功',
    name
  });
}

// ==================== 主入口 ====================
export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const path = url.pathname;
    const method = request.method;

    console.log(`${method} ${path}${url.search}`);

    // 处理 CORS 预检
    if (method === 'OPTIONS') {
      return new Response(null, { headers: corsHeaders });
    }

    try {
      if (path === '/api/clipboard') {
        if (method === 'POST') {
          return await handleCreate(request, env);
        } else if (method === 'GET') {
          return await handleGet(request, env);
        } else if (method === 'DELETE') {
          return await handleDelete(request, env);
        }
      }

      console.warn(`路由未找到: ${path}`);
      return errorResponse('Not Found', 404);
      
    } catch (error) {
      console.error('Unhandled error in fetch:', error);
      return jsonResponse({
        error: 'Internal Server Error',
        detail: error.message,
        stack: error.stack
      }, 500);
    }
  }
};