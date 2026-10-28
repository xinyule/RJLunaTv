import { NextResponse } from 'next/server';
import { DEFAULT_USER_AGENT } from '@/lib/user-agent';
import { validateProxyTargetUrl } from '@/lib/proxy-security';
import * as https from 'https';

export const runtime = 'nodejs';

// https agent with rejectUnauthorized: false for expired-cert image CDNs
const insecureHttpsAgent = new https.Agent({ rejectUnauthorized: false });

async function fetchWithInsecureHttps(imageUrl: string, fetchHeaders: HeadersInit): Promise<Response> {
  return new Promise((resolve, reject) => {
    const urlObj = new URL(imageUrl);
    const options = {
      hostname: urlObj.hostname,
      path: urlObj.pathname + urlObj.search,
      method: 'GET',
      agent: insecureHttpsAgent,
      headers: fetchHeaders as Record<string, string>,
    };
    const req = https.request(options, (res) => {
      const chunks: Buffer[] = [];
      res.on('data', (chunk) => chunks.push(chunk));
      res.on('end', () => {
        const body = Buffer.concat(chunks);
        resolve(new Response(body, {
          status: res.statusCode ?? 200,
          headers: res.headers as Record<string, string>,
        }));
      });
    });
    req.on('error', reject);
    req.end();
  });
}

// 图片代理接口 - 解决防盗链和 Mixed Content 问题
export async function GET(request: Request) {
  const { searchParams } = new URL(request.url);
  const imageUrl = searchParams.get('url');

  if (!imageUrl) {
    return NextResponse.json({ error: 'Missing image URL' }, { status: 400 });
  }

  // SSRF 防护：验证目标 URL
  try {
    await validateProxyTargetUrl(imageUrl);
  } catch (error) {
    console.error('[Image Proxy] SSRF validation failed:', error);
    return NextResponse.json(
      { error: 'Invalid or blocked URL' },
      { status: 403 }
    );
  }

  // 创建 AbortController 用于超时控制
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), 15000); // 15秒超时

  try {
    // 动态设置 Referer 和 Origin（根据图片源域名）
    const imageUrlObj = new URL(imageUrl);
    const sourceOrigin = `${imageUrlObj.protocol}//${imageUrlObj.host}`;

    // 构建请求头
    const fetchHeaders: HeadersInit = {
      'Referer': sourceOrigin + '/',
      'Origin': sourceOrigin,
      'User-Agent': DEFAULT_USER_AGENT,
      'Accept': 'image/avif,image/webp,image/jxl,image/apng,image/svg+xml,image/*,*/*;q=0.8',
      'Accept-Language': 'zh-CN,zh;q=0.9,en;q=0.8',
      'Accept-Encoding': 'gzip, deflate, br',
      'Connection': 'keep-alive',
    };

    // 1.0.1：原先首跳已校验，但 fetch 默认跟随重定向，可经重定向打内网。
    // 改为手动逐跳校验：每跳都重新 validateProxyTargetUrl（上方已校验首跳，
    // 循环内对重定向目标再校验），最多 3 跳；证书过期时仍保留原有的
    // 不校验证书重试，但只针对当跳已校验过的 URL。
    let imageResponse: Response | null = null;
    let currentUrl = imageUrl;
    for (let hop = 0; hop <= 3; hop++) {
      await validateProxyTargetUrl(currentUrl);
      let hopResponse: Response;
      try {
        hopResponse = await fetch(currentUrl, {
          signal: controller.signal,
          headers: fetchHeaders,
          redirect: 'manual',
        });
      } catch (fetchError: any) {
        if (currentUrl.startsWith('https://') && (fetchError.code === 'CERT_HAS_EXPIRED' || fetchError.cause?.code === 'CERT_HAS_EXPIRED' || fetchError.message?.includes('certificate'))) {
          hopResponse = await fetchWithInsecureHttps(currentUrl, fetchHeaders);
        } else {
          throw fetchError;
        }
      }
      const location = hopResponse.headers.get('location');
      if (hopResponse.status >= 300 && hopResponse.status < 400 && location) {
        if (hop === 3) {
          return NextResponse.json({ error: 'Too many redirects' }, { status: 502 });
        }
        hopResponse.body?.cancel();
        currentUrl = new URL(location, currentUrl).toString();
        continue;
      }
      imageResponse = hopResponse;
      break;
    }
    if (!imageResponse) {
      return NextResponse.json({ error: 'Too many redirects' }, { status: 502 });
    }

    clearTimeout(timeoutId);

    if (!imageResponse.ok) {
      const errorResponse = NextResponse.json(
        {
          error: 'Failed to fetch image',
          status: imageResponse.status,
          statusText: imageResponse.statusText
        },
        { status: imageResponse.status }
      );
      // 错误响应不缓存，避免缓存失效的图片链接
      errorResponse.headers.set('Cache-Control', 'no-cache, no-store, must-revalidate');
      return errorResponse;
    }

    const contentType = imageResponse.headers.get('content-type');

    // 安全检查：只转发真正的图片，避免上游返回 HTML 时在本站域名下被当作页面执行
    if (!contentType || !contentType.trim().toLowerCase().startsWith('image/')) {
      imageResponse.body?.cancel();
      return NextResponse.json(
        { error: 'Upstream response is not an image' },
        { status: 415 }
      );
    }

    if (!imageResponse.body) {
      return NextResponse.json(
        { error: 'Image response has no body' },
        { status: 500 }
      );
    }

    // 创建响应头
    const headers = new Headers();
    if (contentType) {
      headers.set('Content-Type', contentType);
    }
    // 防止浏览器 MIME 类型嗅探，强制使用声明的 Content-Type
    headers.set('X-Content-Type-Options', 'nosniff');

    // 传递Content-Length以支持进度显示和更好的缓存（如果上游提供）
    const contentLength = imageResponse.headers.get('content-length');
    if (contentLength) {
      headers.set('Content-Length', contentLength);
    }

    // 设置缓存头 - 缓存7天（604800秒），允许重新验证
    headers.set('Cache-Control', 'public, max-age=604800, stale-while-revalidate=86400');
    headers.set('CDN-Cache-Control', 'public, s-maxage=604800');
    headers.set('Vercel-CDN-Cache-Control', 'public, s-maxage=604800');
    headers.set('Netlify-Vary', 'query');

    // 添加 CORS 支持
    headers.set('Access-Control-Allow-Origin', '*');
    headers.set('Access-Control-Allow-Methods', 'GET, OPTIONS');

    // 直接返回图片流
    return new Response(imageResponse.body, {
      status: 200,
      headers,
    });
  } catch (error: any) {
    clearTimeout(timeoutId);

    // 错误类型判断
    if (error.name === 'AbortError') {
      return NextResponse.json(
        { error: 'Image fetch timeout (15s)' },
        { status: 504 }
      );
    }

    console.error('[Image Proxy] Error fetching image:', error.message);
    return NextResponse.json(
      { error: 'Error fetching image', details: error.message },
      { status: 500 }
    );
  }
}

// 处理 CORS 预检请求
export async function OPTIONS() {
  return new NextResponse(null, {
    status: 204,
    headers: {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type',
    }
  });
}
