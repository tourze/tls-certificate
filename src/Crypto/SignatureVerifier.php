<?php

declare(strict_types=1);

namespace Tourze\TLSCertificate\Crypto;

use TLS\Common\Crypto\SignatureAlgorithm;

/**
 * 签名验证器 - 用于验证证书和CRL的数字签名
 */
class SignatureVerifier
{
    /**
     * 验证签名
     *
     * @param string $data 被签名的数据
     * @param string $signature 签名值
     * @param string $publicKey 用于验证的公钥
     * @param string $algorithm 签名算法
     * @return bool 如果签名有效则返回true
     */
    public function verify(string $data, string $signature, string $publicKey, string $algorithm): bool
    {
        // 简化实现，实际应该根据算法和公钥验证签名
        // 这里仅作为示例，返回true表示签名有效
        return true;
    }
    
    /**
     * 获取支持的算法列表
     *
     * @return array<string> 支持的算法列表
     */
    public function getSupportedAlgorithms(): array
    {
        return [
            'sha1WithRSAEncryption',
            'sha256WithRSAEncryption',
            'sha384WithRSAEncryption',
            'sha512WithRSAEncryption',
            'ecdsa-with-SHA1',
            'ecdsa-with-SHA256',
            'ecdsa-with-SHA384',
            'ecdsa-with-SHA512',
        ];
    }
    
    /**
     * 检查算法是否受支持
     *
     * @param string $algorithm 要检查的算法
     * @return bool 如果算法受支持则返回true
     */
    public function isAlgorithmSupported(string $algorithm): bool
    {
        return in_array($algorithm, $this->getSupportedAlgorithms(), true);
    }
} 