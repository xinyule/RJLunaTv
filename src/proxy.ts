/* eslint-disable no-console */

import { NextRequest, NextResponse } from 'next/server';

import {
  generateSignature,
  getAuthInfoFromCookie,
  getLocalPasswordHash,
  verifyLocalPasswordHash,
} from '@/lib/auth';

// 信任网络配置缓存（从 API 获取）
let trustedNetworkCache: { enabled: boolean; trustedIPs: string[]; blockAdminAccess: boolean } | null = null;
let trustedNetworkCacheTime = 0;
let trustedNetworkFetched = false;
let trustedNetworkVersion = ''; // 跟踪配置版本，用于立即失效缓存

const CACHE_TTL = 86400000; // 24 小时缓存（配置变化时通过 cookie 版本号立即刷新）

// 从环境变量获取信任网络配置（优先）
function getTrustedNetworkFromEnv(): { enabled: boolean; trustedIPs: string[]; blockAdminAccess: boolean } | null {
  const trustedIPs = process.env.TRUSTED_NETWORK_IPS;
  if (!trustedIPs) return null;

  return {
    enabled: true,
    trustedIPs: trustedIPs.split(',').map(ip => ip.trim()).filter(Boolean),
    blockAdminAccess: false,
  };
}

// 从 API 获取信任网络配置（数据库）
async function getTrustedNetworkFromAPI(request: NextRequest): Promise<{ enabled: boolean; trustedIPs: string[]; blockAdminAccess: boolean } | null> {
  const now = Date.now();

  // 检查缓存是否有效
  if (trustedNetworkFetched && trustedNetworkCache !== null) {
    if ((now - trustedNetworkCacheTime) < CACHE_TTL) {
      if (!trustedNetworkCache.enabled) {
        return null;
      }
      return trustedNetworkCache;
    }
  }

  // 如果已经获取过且结果是"未配置"，使用长缓存时间
  if (trustedNetworkFetched && trustedNetworkCache === null) {
    if ((now - trustedNetworkCacheTime) < CACHE_TTL) {
      return null;
    }
  }

  try {
    const url = new URL('/api/server-config', request.url);
    url.searchParams.set('key', 'TrustedNetworkConfig');

    const internalHeaders: Record<string, string> = {
      'x-internal-request': 'true',
    };
    // 1.0.1：内部请求用 PASSWORD 派生的 HMAC 背书，防止外部直接带
    // x-internal-request 头冒充内部请求套取 TrustedNetworkConfig。
    if (process.env.PASSWORD) {
      internalHeaders['x-internal-signature'] = await generateSignature(
        'trusted-network',
        process.env.PASSWORD,
      );
    }
    const response = await fetch(url.toString(), {
      headers: internalHeaders,
    });

    trustedNetworkFetched = true;
    trustedNetworkCacheTime = now;

    if (response.ok) {
      const data = await response.json();
      if (data.TrustedNetworkConfig) {
        trustedNetworkCache = {
          enabled: data.TrustedNetworkConfig.enabled ?? false,
          trustedIPs: data.TrustedNetworkConfig.trustedIPs || [],
          blockAdminAccess: data.TrustedNetworkConfig.blockAdminAccess === true,
        };

        if (!trustedNetworkCache.enabled) {
          return null;
        }

        return trustedNetworkCache;
      }
    }

    // API 返回但没有配置 - 标记为禁用而不是 null，这样走禁用缓存逻辑
    trustedNetworkCache = { enabled: false, trustedIPs: [], blockAdminAccess: false };
  } catch {
    // 请求失败时标记为禁用，使用长缓存时间避免频繁重试
    trustedNetworkCache = { enabled: false, trustedIPs: [], blockAdminAccess: false };
  }

  return null;
}

// 获取信任网络配置（环境变量优先，然后数据库）
async function getTrustedNetworkConfig(request: NextRequest): Promise<{ enabled: boolean; trustedIPs: string[]; blockAdminAccess: boolean } | null> {
  // 环境变量优先
  const envConfig = getTrustedNetworkFromEnv();
  if (envConfig) return envConfig;

  // 检查 cookie 中的配置版本号
  // 管理页面保存配置时会更新这个 cookie，版本号变化时强制刷新缓存
  const cookieVersion = request.cookies.get('tn-version')?.value || '';
  if (cookieVersion && cookieVersion !== trustedNetworkVersion) {
    // 版本号变了，强制清除缓存，立即重新获取
    trustedNetworkCache = null;
    trustedNetworkFetched = false;
    trustedNetworkVersion = cookieVersion;
  }

  // 尝试从数据库获取（内部已处理禁用状态的缓存优化）
  return await getTrustedNetworkFromAPI(request);
}

// 常见弱默认密码/凭据黑名单（小写比对）。命中时视同未配置密码，
// 强制走 /warning 页而不是静默放行——这类值通常来自教程截图、示例配置复制粘贴。
const WEAK_DEFAULT_CREDENTIALS = new Set([
  'admin',
  'admin123',
  'password',
  'password123',
  '123456',
  '12345678',
  'changeme',
  'letmein',
  'lunatv',
  'moontv',
]);

function isWeakDefaultCredential(value: string): boolean {
  return WEAK_DEFAULT_CREDENTIALS.has(value.toLowerCase());
}

// 获取客户端 IP
function getClientIP(request: NextRequest): string {
  // 1.0.1：信任网络判定不能直接取 X-Forwarded-For 首项——首项可由客户端
  // 任意伪造。优先取受信任代理写入的 cf-connecting-ip / x-real-ip，
  // 只有都没有时才取 XFF 末项（最接近代理的一跳），与登录限流保持一致。
  return (
    request.headers.get('cf-connecting-ip')?.trim() ||
    request.headers.get('x-real-ip')?.trim() ||
    request.headers.get('x-forwarded-for')?.split(',').pop()?.trim() ||
    'unknown'
  );
}

// 简化的 IP/CIDR 匹配（Edge Runtime 兼容）
function isIPInCIDR(clientIP: string, cidr: string): boolean {
  // 处理通配符
  if (cidr === '*') return true;

  // 检测 IPv6
  const isClientIPv6 = clientIP.includes(':');
  const isCIDRIPv6 = cidr.includes(':');

  // IPv4 和 IPv6 不能互相匹配
  if (isClientIPv6 !== isCIDRIPv6) return false;

  if (isClientIPv6) {
    // IPv6 简化匹配：只支持精确匹配和简单前缀匹配
    if (cidr.includes('/')) {
      const [network] = cidr.split('/');
      // 简化：检查是否以相同前缀开始
      return clientIP.toLowerCase().startsWith(network.toLowerCase().replace(/:+$/, ''));
    }
    return clientIP.toLowerCase() === cidr.toLowerCase();
  }

  // IPv4 CIDR 匹配
  if (cidr.includes('/')) {
    const [network, maskStr] = cidr.split('/');
    const mask = parseInt(maskStr, 10);

    const networkParts = network.split('.').map(Number);
    const clientParts = clientIP.split('.').map(Number);

    if (clientParts.length !== 4 || networkParts.length !== 4) return false;
    if (clientParts.some(p => isNaN(p)) || networkParts.some(p => isNaN(p))) return false;

    // 转换为 32 位整数
    const networkInt = (networkParts[0] << 24) | (networkParts[1] << 16) | (networkParts[2] << 8) | networkParts[3];
    const clientInt = (clientParts[0] << 24) | (clientParts[1] << 16) | (clientParts[2] << 8) | clientParts[3];

    // 生成掩码
    const maskInt = mask === 0 ? 0 : (~0 << (32 - mask)) >>> 0;

    return (networkInt & maskInt) === (clientInt & maskInt);
  }

  // 精确 IP 匹配
  return clientIP === cidr;
}

// 检查 IP 是否在信任网络中
function isIPTrusted(clientIP: string, trustedIPs: string[]): boolean {
  return trustedIPs.some(trustedIP => isIPInCIDR(clientIP, trustedIP.trim()));
}

// 生成信任网络的自动登录 cookie
async function generateTrustedAuthCookie(request: NextRequest): Promise<NextResponse> {
  const response = NextResponse.next();

  const storageType = process.env.NEXT_PUBLIC_STORAGE_TYPE || 'localstorage';
  const username = process.env.USERNAME || 'admin';

  if (storageType === 'localstorage') {
    // localstorage 模式：设置密码哈希 cookie（不存明文）
    const authInfo = {
      password: await getLocalPasswordHash(),
      loginTime: Date.now(),
    };
    response.cookies.set('user_auth', JSON.stringify(authInfo), {
      httpOnly: false,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'lax',
      maxAge: 7 * 24 * 60 * 60, // 7 天
    });
  } else {
    // 数据库模式：信任网络签发的 cookie 也必须带 HMAC 签名（1.0.1）。
    // 旧的无签名 trustedNetwork cookie 在下一次校验时会被拒绝，
    // 信任网络内的用户会由自动登录分支重新签发，无需手动干预。
    const signature = process.env.PASSWORD
      ? await generateSignature(username, process.env.PASSWORD)
      : undefined;
    const authInfo: Record<string, unknown> = {
      username,
      trustedNetwork: true,
      timestamp: Date.now(),
      loginTime: Date.now(),
      role: 'owner',
    };
    if (signature) authInfo.signature = signature;
    response.cookies.set('user_auth', JSON.stringify(authInfo), {
      httpOnly: false,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'lax',
      maxAge: 7 * 24 * 60 * 60, // 7 天
    });
  }

  return response;
}

export async function proxy(request: NextRequest) {
  const { pathname } = request.nextUrl;

  // 处理 /adult/ 路径前缀，重写为实际 API 路径
  if (pathname.startsWith('/adult/')) {
    // 移除 /adult 前缀
    const newPathname = pathname.replace(/^\/adult/, '');

    // 创建新的 URL
    const url = request.nextUrl.clone();
    url.pathname = newPathname || '/';

    // 添加 adult=1 参数（如果还没有）
    if (!url.searchParams.has('adult')) {
      url.searchParams.set('adult', '1');
    }

    // 重写请求
    const response = NextResponse.rewrite(url);

    // 设置响应头标识成人内容模式
    response.headers.set('X-Content-Mode', 'adult');

    // 继续执行认证检查（对于 API 路径）
    if (newPathname.startsWith('/api')) {
      // 将重写后的请求传递给认证逻辑
      const modifiedRequest = new NextRequest(url, request);
      return handleAuthentication(modifiedRequest, newPathname, response);
    }

    return response;
  }

  // 跳过不需要认证的路径
  if (shouldSkipAuth(pathname)) {
    return NextResponse.next();
  }

  return handleAuthentication(request, pathname);
}

// 提取认证处理逻辑为单独的函数
async function handleAuthentication(
  request: NextRequest,
  pathname: string,
  response?: NextResponse
) {
  const storageType = process.env.NEXT_PUBLIC_STORAGE_TYPE || 'localstorage';

  // 🔥 检查信任网络模式（环境变量优先，然后数据库）
  const trustedNetworkConfig = await getTrustedNetworkConfig(request);
  if (trustedNetworkConfig?.enabled && trustedNetworkConfig.trustedIPs.length > 0) {
    const clientIP = getClientIP(request);

    if (isIPTrusted(clientIP, trustedNetworkConfig.trustedIPs)) {
      // 加固开关：禁止信任网络访客访问后台
      // 命中 /admin 或 /api/admin/* 时，跳过自动登录分支，落到下方密码/签名校验
      const isAdminPath =
        pathname.startsWith('/admin') || pathname.startsWith('/api/admin');
      if (trustedNetworkConfig.blockAdminAccess && isAdminPath) {
        // 不签发也不复用 trustedNetwork cookie，让请求走标准认证流程
        // 后续签名校验仍会拦住无签名 cookie，且 blockAdminAccess 会再次生效
      } else {
        console.log(`[Middleware] Trusted network auto-login for IP: ${clientIP}`);

        // 检查是否已经有有效的认证 cookie：只复用验签通过的 cookie，
        // 无签名的 trustedNetwork 标记不再视为有效（1.0.1），下面会重新签发。
        const existingAuth = getAuthInfoFromCookie(request);
        if (existingAuth) {
          if (storageType === 'localstorage') {
            if (existingAuth.password && (await verifyLocalPasswordHash(existingAuth.password))) {
              return response || NextResponse.next();
            }
          } else if (existingAuth.username && existingAuth.signature && process.env.PASSWORD) {
            if (await verifySignature(existingAuth.username, existingAuth.signature, process.env.PASSWORD)) {
              return response || NextResponse.next();
            }
          }
        }

        // 没有认证 cookie，自动生成并设置
        return await generateTrustedAuthCookie(request);
      }
    }
  }

  if (!process.env.PASSWORD) {
    // 未设置密码，重定向到警告页面
    const warningUrl = new URL('/warning', request.url);
    return NextResponse.redirect(warningUrl);
  }

  if (isWeakDefaultCredential(process.env.PASSWORD)) {
    // 已设置密码，但命中常见弱默认值黑名单（admin/admin123/password等）——
    // 用不同的 reason 参数区分，避免用户误以为环境变量没生效
    const warningUrl = new URL('/warning', request.url);
    warningUrl.searchParams.set('reason', 'weak-password');
    return NextResponse.redirect(warningUrl);
  }

  // 从cookie获取认证信息
  const authInfo = getAuthInfoFromCookie(request);

  if (!authInfo) {
    return handleAuthFailure(request, pathname);
  }

  // localstorage模式：在middleware中完成验证
  if (storageType === 'localstorage') {
    if (!authInfo.password || !(await verifyLocalPasswordHash(authInfo.password))) {
      return handleAuthFailure(request, pathname);
    }
    return response || NextResponse.next();
  }

  // 其他模式：只验证签名。1.0.1 删除了 trustedNetwork 标记短路：
  // 旧的无签名信任网络 cookie 曾可从任意 IP 伪造后直接放行。
  // 信任网络签发的 cookie 现在也带签名（见 generateTrustedAuthCookie），
  // 因此走下方统一的签名校验即可；blockAdminAccess 仍在签名通过后生效。
  if (authInfo.trustedNetwork) {
    if (
      trustedNetworkConfig?.blockAdminAccess &&
      (pathname.startsWith('/admin') || pathname.startsWith('/api/admin'))
    ) {
      return NextResponse.redirect(new URL('/login', request.url));
    }
    // 不再直接放行，继续走签名校验
  }

  // 检查是否有用户名（非localStorage模式下密码不存储在cookie中）
  if (!authInfo.username || !authInfo.signature) {
    return handleAuthFailure(request, pathname);
  }

  // 验证签名（如果存在）
  if (authInfo.signature) {
    const isValidSignature = await verifySignature(
      authInfo.username,
      authInfo.signature,
      process.env.PASSWORD || ''
    );

    // 签名验证通过且未超 7 天即可（1.0.1：原先服务端不校验时间戳，
    // Cookie 7 天有效期只靠浏览器，窃取后可无限重放）
    if (isValidSignature) {
      if (authInfo.timestamp) {
        const age = Date.now() - authInfo.timestamp;
        if (!Number.isFinite(age) || age < 0 || age > 7 * 24 * 60 * 60 * 1000) {
          return handleAuthFailure(request, pathname);
        }
      }
      return response || NextResponse.next();
    }
  }

  // 签名验证失败或不存在签名
  return handleAuthFailure(request, pathname);
}

// 验证签名
async function verifySignature(
  data: string,
  signature: string,
  secret: string
): Promise<boolean> {
  const encoder = new TextEncoder();
  const keyData = encoder.encode(secret);
  const messageData = encoder.encode(data);

  try {
    // 导入密钥
    const key = await crypto.subtle.importKey(
      'raw',
      keyData,
      { name: 'HMAC', hash: 'SHA-256' },
      false,
      ['verify']
    );

    // 将十六进制字符串转换为Uint8Array
    const signatureBuffer = new Uint8Array(
      signature.match(/.{1,2}/g)?.map((byte) => parseInt(byte, 16)) || []
    );

    // 验证签名
    return await crypto.subtle.verify(
      'HMAC',
      key,
      signatureBuffer,
      messageData
    );
  } catch (error) {
    console.error('签名验证失败:', error);
    return false;
  }
}

// 处理认证失败的情况
function handleAuthFailure(
  request: NextRequest,
  pathname: string
): NextResponse {
  // 如果是 API 路由，返回 401 状态码
  if (pathname.startsWith('/api')) {
    return new NextResponse('Unauthorized', { status: 401 });
  }

  // 否则重定向到登录页面
  const loginUrl = new URL('/login', request.url);
  // 保留完整的URL，包括查询参数
  const fullUrl = `${pathname}${request.nextUrl.search}`;
  loginUrl.searchParams.set('redirect', fullUrl);
  return NextResponse.redirect(loginUrl);
}

// 判断是否需要跳过认证的路径
function shouldSkipAuth(pathname: string): boolean {
  const skipPaths = [
    '/_next',
    '/favicon.ico',
    '/robots.txt',
    '/manifest.json',
    '/icons/',
    '/logo.png',
    '/screenshot.png',
    '/api/telegram/', // Telegram API 端点
    '/api/cache/', // 缓存 API 端点（内部使用，无需认证）
    '/api/client-log', // 客户端日志收集端点（无需认证）
  ];

  return skipPaths.some((path) => pathname.startsWith(path));
}

// 配置middleware匹配规则
export const config = {
  matcher: [
    '/((?!_next/static|_next/image|favicon.ico|login|register|oidc-register|warning|api/login|api/register|api/logout|api/cron|api/server-config|api/tvbox|api/live/merged|api/parse|api/bing-wallpaper|api/proxy/|api/telegram/|api/auth/oidc/|api/watch-room/).*)',
  ],
};
