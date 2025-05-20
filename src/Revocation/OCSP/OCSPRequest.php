<?php

declare(strict_types=1);

namespace Tourze\TLSCertificate\Revocation\OCSP;

use Tourze\TLSCertificate\Certificate\X509Certificate;
use Tourze\TLSCertificate\Exception\OCSPException;

/**
 * OCSP请求类 - 用于构建OCSP请求
 */
class OCSPRequest
{
    /**
     * @var string 证书序列号
     */
    private string $serialNumber;
    
    /**
     * @var string 颁发者名称散列值
     */
    private string $issuerNameHash;
    
    /**
     * @var string 颁发者公钥散列值
     */
    private string $issuerKeyHash;
    
    /**
     * @var string 散列算法
     */
    private string $hashAlgorithm;
    
    /**
     * @var string|null 随机数
     */
    private ?string $nonce;
    
    /**
     * @var string|null 编码的请求数据
     */
    private ?string $encodedRequest = null;
    
    /**
     * 构造函数
     *
     * @param string $serialNumber 证书序列号
     * @param string $issuerNameHash 颁发者名称散列值
     * @param string $issuerKeyHash 颁发者公钥散列值
     * @param string $hashAlgorithm 散列算法
     * @param string|null $nonce 随机数
     */
    public function __construct(
        string $serialNumber,
        string $issuerNameHash,
        string $issuerKeyHash,
        string $hashAlgorithm = 'sha1',
        ?string $nonce = null
    ) {
        $this->serialNumber = $serialNumber;
        $this->issuerNameHash = $issuerNameHash;
        $this->issuerKeyHash = $issuerKeyHash;
        $this->hashAlgorithm = $hashAlgorithm;
        $this->nonce = $nonce;
    }
    
    /**
     * 从证书创建OCSP请求
     *
     * @param X509Certificate $certificate 要检查的证书
     * @param X509Certificate $issuerCertificate 颁发者证书
     * @param string $hashAlgorithm 散列算法
     * @param bool $includeNonce 是否包含随机数
     * @return self
     * @throws OCSPException 如果创建请求失败
     */
    public static function fromCertificate(
        X509Certificate $certificate,
        X509Certificate $issuerCertificate,
        string $hashAlgorithm = 'sha1',
        bool $includeNonce = true
    ): self {
        try {
            // 获取证书序列号
            $serialNumber = $certificate->getSerialNumber();
            
            // 计算颁发者名称散列
            $issuerName = $issuerCertificate->getSubjectDN(true); // 获取DER编码的主题
            $issuerNameHash = hash($hashAlgorithm, $issuerName, true);
            
            // 计算颁发者公钥散列
            $issuerPublicKey = $issuerCertificate->getPublicKeyDER();
            $issuerKeyHash = hash($hashAlgorithm, $issuerPublicKey, true);
            
            // 生成随机数（如果需要）
            $nonce = $includeNonce ? bin2hex(random_bytes(16)) : null;
            
            return new self(
                $serialNumber,
                bin2hex($issuerNameHash),
                bin2hex($issuerKeyHash),
                $hashAlgorithm,
                $nonce
            );
        } catch (\Exception $e) {
            throw new OCSPException('创建OCSP请求失败: ' . $e->getMessage(), 0, $e);
        }
    }
    
    /**
     * 构建DER编码的OCSP请求
     *
     * @return string DER编码的OCSP请求
     * @throws OCSPException 如果构建请求失败
     */
    public function encode(): string
    {
        if ($this->encodedRequest !== null) {
            return $this->encodedRequest;
        }
        
        try {
            // 注意：这里简化了实现，实际应该使用ASN.1库构建OCSP请求
            // RFC 6960 定义了OCSP请求的ASN.1结构
            
            // 这是一个基本的骨架实现
            // 在实际项目中，应该使用ASN.1库如phpseclib来构建请求
            
            // TODO: 实现完整的ASN.1编码
            $this->encodedRequest = ''; // 占位符
            
            return $this->encodedRequest;
        } catch (\Exception $e) {
            throw new OCSPException('编码OCSP请求失败: ' . $e->getMessage(), 0, $e);
        }
    }
    
    /**
     * 获取请求的证书序列号
     *
     * @return string
     */
    public function getSerialNumber(): string
    {
        return $this->serialNumber;
    }
    
    /**
     * 获取颁发者名称散列值
     *
     * @return string
     */
    public function getIssuerNameHash(): string
    {
        return $this->issuerNameHash;
    }
    
    /**
     * 获取颁发者公钥散列值
     *
     * @return string
     */
    public function getIssuerKeyHash(): string
    {
        return $this->issuerKeyHash;
    }
    
    /**
     * 获取散列算法
     *
     * @return string
     */
    public function getHashAlgorithm(): string
    {
        return $this->hashAlgorithm;
    }
    
    /**
     * 获取随机数
     *
     * @return string|null
     */
    public function getNonce(): ?string
    {
        return $this->nonce;
    }
} 