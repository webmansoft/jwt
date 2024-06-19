<?php
declare(strict_types=1);

namespace Webmansoft\Jwt;

use Exception;
use UnexpectedValueException;
use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use Firebase\JWT\ExpiredException;
use Firebase\JWT\BeforeValidException;
use Firebase\JWT\SignatureInvalidException;
use Webmansoft\Jwt\Exception\JwtTokenException;
use Webmansoft\Jwt\Exception\JwtConfigException;
use Webmansoft\Jwt\Exception\JwtCacheTokenException;
use Webmansoft\Jwt\Exception\JwtTokenExpiredException;

class JwtToken
{
    /** WEB Client. */
    public const TOKEN_CLIENT_WEB = 'WEB';

    /** Mobile Client. */
    public const TOKEN_CLIENT_MOBILE = 'MOBILE';

    /**
     * 获取当前登录ID
     * @param bool $throw 是否抛出错误
     * @return int
     */
    public static function getUserId(bool $throw = true): int
    {
        return intval(self::getExtendVal('id', $throw));
    }

    /**
     * 获取指定令牌扩展内容字段的值
     * @param string $field
     * @param bool $throw 是否抛出错误
     * @return array|int|string
     */
    public static function getExtendVal(string $field, bool $throw = true): array|int|string
    {
        return self::getTokenExtend($throw)[$field] ?? '';
    }

    /**
     * 获取指定令牌扩展内容
     * @param bool $throw 是否抛出错误
     * @return array
     */
    public static function getExtend(bool $throw = true): array
    {
        return self::getTokenExtend($throw);
    }

    /**
     * 生成令牌
     * @param array $extend
     * @return array
     */
    public static function generateToken(array $extend): array
    {
        if (!isset($extend['id'])) {
            throw new JwtTokenException('缺少全局唯一字段：id');
        }

        $config = self::getConfig();
        $config['access_exp'] = $extend['access_exp'] ?? $config['access_exp'];
        $payload = self::generatePayload($config, $extend);
        $secret_key = self::getPrivateKey($config['algorithm']);
        $token = [
            'token_type' => 'Bearer',
            'expires_in' => $config['access_exp'],
            'access_token' => self::makeToken($payload['access_payload'], $secret_key, $config['algorithm'])
        ];

        if ($config['is_single_device']) {
            $client = $extend['client'] ?? self::TOKEN_CLIENT_WEB;
            RedisHandler::generateToken($config['cache_token_prefix'], (string)$client, (string)$extend['id'], $config['access_exp'], $token['access_token']);
        }

        return $token;
    }

    /**
     * 验证令牌
     * @param string|null $token
     * @param bool $throw 是否抛出错误
     * @return array
     */
    public static function verify(string|null $token = null, bool $throw = true): array
    {
        $token = $token ?? self::getTokenFromHeaders($throw);
        if ($token === false) {
            return [];
        }

        try {
            return self::verifyToken($token);
        } catch (SignatureInvalidException) {
            if ($throw) {
                throw new JwtTokenException('身份验证令牌无效', 401011);
            }
        } catch (BeforeValidException) {
            if ($throw) {
                throw new JwtTokenException('身份验证令牌尚未生效', 401012);
            }
        } catch (ExpiredException) {
            if ($throw) {
                throw new JwtTokenExpiredException('身份验证会话已过期，请重新登录', 401013);
            }
        } catch (UnexpectedValueException) {
            if ($throw) {
                throw new JwtTokenException('获取的扩展字段不存在', 401014);
            }
        } catch (JwtCacheTokenException|Exception $exception) {
            if ($throw) {
                throw new JwtTokenException($exception->getMessage(), 401015);
            }
        }

        return [];
    }

    /**
     * 获取扩展字段
     * @param bool $throw 是否抛出错误
     * @return array
     */
    private static function getTokenExtend(bool $throw = true): array
    {
        $data = self::verify(null, $throw);
        var_dump($data);
        return $data['extend'] ?? [];
    }

    /**
     * 获令牌有效期剩余时长
     * @return int
     */
    public static function getTokenExp(): int
    {
        return (int)self::verify()['exp'] - time();
    }

    /**
     * 获取Header头部authorization令牌
     * @param bool $throw 是否抛出错误
     * @return string|bool
     */
    private static function getTokenFromHeaders(bool $throw = true): string|bool
    {
        $authorization = request()->header('authorization');
        if (!$authorization || 'undefined' == $authorization) {
            $config = self::getConfig();
            if (!isset($config['is_support_get_token']) || false === $config['is_support_get_token']) {
                if ($throw) {
                    throw new JwtTokenException('请求未携带authorization信息', 401000);
                } else {
                    return false;
                }
            }

            $authorization = request()->get($config['is_support_get_token_key']);
            if (empty($authorization)) {
                if ($throw) {
                    throw new JwtTokenException('请求未携带authorization信息', 401000);
                } else {
                    return false;
                }
            }

            $authorization = 'Bearer ' . $authorization;
        }

        if (2 != substr_count($authorization, '.')) {
            if ($throw) {
                throw new JwtTokenException('非法的authorization信息', 401001);
            } else {
                return false;
            }
        }

        if (2 != count(explode(' ', $authorization))) {
            if ($throw) {
                throw new JwtTokenException('Bearer验证中的凭证格式有误，中间必须只有一个空格', 401000);
            } else {
                return false;
            }
        }

        [$type, $token] = explode(' ', $authorization);
        if ('Bearer' !== $type) {
            if ($throw) {
                throw new JwtTokenException('接口认证方式需为Bearer', 401000);
            } else {
                return false;
            }
        }

        if (!$token || 'undefined' === $token) {
            if ($throw) {
                throw new JwtTokenException('尝试获取的Authorization信息不存在', 401000);
            } else {
                return false;
            }
        }

        return $token;
    }

    /**
     * 校验令牌
     * @param string $token
     * @return array
     */
    private static function verifyToken(string $token): array
    {
        $config = self::getConfig();
        $public_key = self::getPublicKey($config['algorithm']);
        JWT::$leeway = $config['leeway'];
        $decoded = JWT::decode($token, new Key($public_key, $config['algorithm']));
        $decode_token = json_decode(json_encode($decoded), true);
        if ($config['is_single_device']) {
            $prefix = $config['cache_token_prefix'];
            $client = $decode_token['extend']['client'] ?? self::TOKEN_CLIENT_WEB;
            RedisHandler::verifyToken($prefix, $client, $decode_token['extend']['id'], $token);
        }

        return $decode_token;
    }

    /**
     * 生成令牌
     * @param array $payload 载荷信息
     * @param string $secret_key 签名key
     * @param string $algorithm 算法
     * @return string
     */
    private static function makeToken(array $payload, string $secret_key, string $algorithm): string
    {
        return JWT::encode($payload, $secret_key, $algorithm);
    }

    /**
     * 获取加密载体
     * @param array $config 配置文件
     * @param array $extend 自定义扩展信息
     * @return array
     */
    private static function generatePayload(array $config, array $extend): array
    {
        $base_payload = [
            'iss' => $config['iss'], // 签发者
            'aud' => $config['iss'], // 接收该JWT的一方
            'iat' => time(), // 签发时间
            'nbf' => time() + ($config['nbf'] ?? 0), // 某个时间点后才能访问
            'exp' => time() + $config['access_exp'], // 过期时间
            'extend' => $extend // 自定义扩展信息
        ];
        $payload['access_payload'] = $base_payload;
        return $payload;
    }

    /**
     * 根据签名算法获取【公钥】签名值
     * @param string $algorithm 算法
     * @return string
     */
    private static function getPublicKey(string $algorithm): string
    {
        $config = self::getConfig();
        return match ($algorithm) {
            'RS512', 'RS256' => $config['access_public_key'],
            default => $config['access_secret_key'],
        };
    }

    /**
     * 根据签名算法获取【私钥】签名值
     * @param string $algorithm 算法
     * @return string
     */
    private static function getPrivateKey(string $algorithm): string
    {
        $config = self::getConfig();
        return match ($algorithm) {
            'RS512', 'RS256' => $config['access_private_key'],
            default => $config['access_secret_key'],
        };
    }

    /**
     * 获取配置文件
     * @return array
     */
    private static function getConfig(): array
    {
        $config = config('plugin.webmansoft.jwt.app.jwt');
        if (empty($config)) {
            throw new JwtConfigException('jwt配置文件不存在');
        }

        return $config;
    }

    /**
     * 注销令牌
     * @param string $client
     * @return bool
     */
    public static function clear(string $client = self::TOKEN_CLIENT_WEB): bool
    {
        $config = self::getConfig();
        if ($config['is_single_device']) {
            return RedisHandler::clearToken($config['cache_token_prefix'], $client, self::getUserId());
        }

        return true;
    }
}