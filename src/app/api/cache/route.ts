import { NextRequest, NextResponse } from 'next/server';
import { db } from '@/lib/db';

import { getAdminRoleFromRequest } from '@/lib/admin-auth';

// 1.0.1：/api/cache 原先已登录用户可读写任意缓存键，与 Telegram 令牌、
// 登录限流计数等关键键共享同一命名空间。客户端实际只用以下公开缓存前缀，
// 非管理员请求仅放行这些前缀；管理员（已验签）仍可全量操作。
const CLIENT_CACHE_PREFIXES = ['douban-', 'tmdb-', 'bangumi-', 'danmu-cache-', 'shortdrama-'];
async function isCacheKeyAllowed(request: NextRequest, key: string): Promise<boolean> {
  if (await getAdminRoleFromRequest(request)) return true;
  return CLIENT_CACHE_PREFIXES.some((prefix) => key.startsWith(prefix));
}

export async function GET(request: NextRequest) {
  try {
    const { searchParams } = new URL(request.url);
    const key = searchParams.get('key');

    if (!key) {
      return NextResponse.json({ error: 'Key is required' }, { status: 400 });
    }
    if (!(await isCacheKeyAllowed(request, key))) {
      return NextResponse.json({ error: 'Forbidden cache key' }, { status: 403 });
    }

    console.log(`🔍 API缓存请求: ${key}`);

    // 现在可以安全地调用 db.getCache，Upstash 的 getCache 已经修复
    const data = await db.getCache(key);
    console.log(`✅ API缓存结果: ${data ? '命中' : '未命中'}`);
    return NextResponse.json({ data });
  } catch (error) {
    console.error(`❌ API缓存错误 (key: ${request.nextUrl.searchParams.get('key')}):`, error);
    console.error('错误详情:', {
      message: error instanceof Error ? error.message : 'Unknown error',
      stack: error instanceof Error ? error.stack : undefined,
      name: error instanceof Error ? error.name : undefined
    });
    return NextResponse.json({ data: null }, { status: 200 }); // 确保返回 200 而不是 500
  }
}

export async function POST(request: NextRequest) {
  try {
    const body = await request.json();
    const { key, data, expireSeconds } = body;

    if (!key) {
      return NextResponse.json({ error: 'Key is required' }, { status: 400 });
    }
    if (!(await isCacheKeyAllowed(request, key))) {
      return NextResponse.json({ error: 'Forbidden cache key' }, { status: 403 });
    }

    console.log(`📝 API缓存写入: ${key}, 过期时间: ${expireSeconds}秒`);

    await db.setCache(key, data, expireSeconds);

    console.log(`✅ API缓存写入成功: ${key}`);
    return NextResponse.json({ success: true });
  } catch (error) {
    console.error('❌ API缓存写入失败:', error);
    console.error('错误详情:', {
      message: error instanceof Error ? error.message : 'Unknown error',
      stack: error instanceof Error ? error.stack : undefined,
      name: error instanceof Error ? error.name : undefined
    });
    return NextResponse.json({ error: 'Failed to set cache' }, { status: 500 });
  }
}

export async function DELETE(request: NextRequest) {
  try {
    const { searchParams } = new URL(request.url);
    const key = searchParams.get('key');
    const prefix = searchParams.get('prefix');

    if (prefix) {
      if (!(await isCacheKeyAllowed(request, prefix))) {
        return NextResponse.json({ error: 'Forbidden cache prefix' }, { status: 403 });
      }
      await db.clearExpiredCache(prefix);
    } else if (key) {
      if (!(await isCacheKeyAllowed(request, key))) {
        return NextResponse.json({ error: 'Forbidden cache key' }, { status: 403 });
      }
      await db.deleteCache(key);
    } else {
      return NextResponse.json({ error: 'Key or prefix is required' }, { status: 400 });
    }

    return NextResponse.json({ success: true });
  } catch (error) {
    console.error('Delete cache error:', error);
    return NextResponse.json({ error: 'Failed to delete cache' }, { status: 500 });
  }
}