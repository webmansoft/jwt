<?php
declare(strict_types=1);

namespace Webmansoft\Jwt;

use support\Redis;
use Webmansoft\Jwt\Exception\JwtCacheTokenException;

class RedisHandler
{
    /**
     * 生成缓存令牌
     * @param string $prefix 前缀
     * @param string $client 登录设备
     * @param int|string $uid 用户编号
     * @param int $ttl 到期时间
     * @param string $token
     * @return void
     */
    public static function generateToken(string $prefix, string $client, int|string $uid, int $ttl, string $token): void
    {
        $key = $prefix . $client . ':' . $uid;
        Redis::del($key);
        Redis::setex($key, $ttl, $token);
    }

    /**
     * 检查设备缓存令牌
     * @param string $prefix 前缀
     * @param string $client 登录设备
     * @param int|string $uid 用户编号
     * @param string $token
     * @return bool
     */
    public static function verifyToken(string $prefix, string $client, int|string $uid, string $token): bool
    {
        $key = $prefix . $client . ':' . $uid;
        if (!Redis::exists($key)) {
            throw new JwtCacheTokenException('该账号已在其他设备登录，被系统强制下线');
        }

        if (Redis::get($key) != $token) {
            throw new JwtCacheTokenException('身份验证会话已过期，请再次登录');
        }

        return true;
    }

    /**
     * 清理缓存令牌
     * @param string $prefix 前缀
     * @param string $client 登录设备
     * @param int|string $uid 用户编号
     * @return bool
     */
    public static function clearToken(string $prefix, string $client, int|string $uid): bool
    {
        Redis::del($prefix . $client . ':' . $uid);
        return true;
    }
}
