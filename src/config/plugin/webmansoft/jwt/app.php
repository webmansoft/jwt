<?php

return [
    'enable' => true,
    'jwt' => [
        /** 算法类型 HS256、HS384、HS512、RS256、RS384、RS512、ES256、ES384、Ed25519 */
        'algorithm' => 'HS256',

        /** access令牌秘钥 */
        'access_secret_key' => '20240619',

        /** access令牌过期时间，单位：秒。默认 2 小时 */
        'access_exp' => 604800, // 7200,

        /** 令牌签发者 */
        'iss' => 'webman-soft',

        /** 某个时间点后才能访问，单位秒。（如：30 表示当前时间30秒后才能使用） */
        'nbf' => 0,

        /** 时钟偏差冗余时间，单位秒。建议这个余地应该不大于几分钟 */
        'leeway' => 60,

        /** 是否允许单设备登录，默认不允许 false */
        'is_single_device' => false,

        /** 缓存令牌时间，单位：秒。默认 7 天 */
        'cache_token_ttl' => 604800,

        /** 缓存令牌前缀，默认 JWT:TOKEN: */
        'cache_token_prefix' => 'JWT:TOKEN:',

        /** 是否支持 get 请求获取令牌 */
        'is_support_get_token' => false,

        /** GET 请求获取令牌请求key */
        'is_support_get_token_key' => 'authorization',

        /** access令牌私钥 */
        'access_private_key' => '',

        /** access令牌公钥 */
        'access_public_key' => '',
    ],
];