/* eslint-disable no-console,@typescript-eslint/no-explicit-any */

import { NextRequest, NextResponse } from 'next/server';

import { getAdminRoleFromRequest } from '@/lib/admin-auth';

export const runtime = 'nodejs';

// 导入 cron route 中的统计数据
// 注意：这里我们需要从父模块导出 currentCronStats
let cachedStats: any = null;

export async function GET(request: NextRequest) {
  // 1.0.1：统计接口原先无鉴权。CRON_SECRET 通过时放行，否则须为已验签的管理员。
  const cronSecret = process.env.CRON_SECRET;
  const authHeader = request.headers.get('authorization') || '';
  const provided =
    request.headers.get('x-cron-secret') ||
    (authHeader.startsWith('Bearer ') ? authHeader.slice(7) : '');
  const hasCronSecret = !!cronSecret && provided === cronSecret;
  if (!hasCronSecret && !(await getAdminRoleFromRequest(request))) {
    return NextResponse.json({ success: false, message: 'Unauthorized' }, { status: 401 });
  }
  try {
    // 从全局获取最新的 cron 统计数据
    // 这里需要修改 cron/route.ts 来导出统计数据
    const stats = (global as any).currentCronStats || cachedStats;

    if (!stats) {
      return NextResponse.json({
        success: false,
        message: 'No cron statistics available yet. Please run cron job first.',
        timestamp: new Date().toISOString(),
      }, { status: 404 });
    }

    // 缓存统计数据
    cachedStats = stats;

    return NextResponse.json({
      success: true,
      message: 'Cron statistics retrieved successfully',
      timestamp: new Date().toISOString(),
      stats: {
        startTime: stats.startTime,
        endTime: stats.endTime,
        duration: stats.duration,
        durationSeconds: stats.duration ? (stats.duration / 1000).toFixed(2) : null,
        memoryUsed: stats.memoryUsed ? `${stats.memoryUsed.toFixed(2)} MB` : null,
        dbQueries: stats.dbQueries,
        tasks: stats.tasks,
      },
    });
  } catch (error) {
    console.error('Failed to retrieve cron stats:', error);
    return NextResponse.json({
      success: false,
      message: 'Failed to retrieve cron statistics',
      error: error instanceof Error ? error.message : 'Unknown error',
      timestamp: new Date().toISOString(),
    }, { status: 500 });
  }
}
