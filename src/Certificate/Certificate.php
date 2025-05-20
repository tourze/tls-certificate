<?php

declare(strict_types=1);

namespace Tourze\TLSCertificate\Certificate;

use DateTimeImmutable;
use Tourze\TLSCertificate\Exception\CertificateException;

/**
 * 通用证书类
 * 
 * 表示一个X.509证书，包含所有证书字段和验证方法
 */
class Certificate
{
    /**
     * @var int|null 证书版本
     */
    private ?int $version = null;
    
    /**
     * @var string|null 序列号
     */
    private ?string $serialNumber = null;
    
    /**
     * @var string|null 签名算法
     */
    private ?string $signatureAlgorithm = null;
    
    /**
     * @var array|null 颁发者信息
     */
    private ?array $issuer = null;
    
    /**
     * @var array|null 主题信息
     */
    private ?array $subject = null;
    
    /**
     * @var DateTimeImmutable|null 证书有效期开始时间
     */
    private ?DateTimeImmutable $notBefore = null;
    
    /**
     * @var DateTimeImmutable|null 证书有效期结束时间
     */
    private ?DateTimeImmutable $notAfter = null;
    
    /**
     * @var string|null 公钥
     */
    private ?string $publicKey = null;
    
    /**
     * 获取证书版本
     *
     * @return int|null
     */
    public function getVersion(): ?int
    {
        return $this->version;
    }
    
    /**
     * 设置证书版本
     *
     * @param int $version 证书版本
     * @return self
     * @throws CertificateException 当版本号无效时
     */
    public function setVersion(int $version): self
    {
        if ($version < 0) {
            throw new CertificateException('无效的证书版本');
        }
        
        $this->version = $version;
        return $this;
    }
    
    /**
     * 获取序列号
     *
     * @return string|null
     */
    public function getSerialNumber(): ?string
    {
        return $this->serialNumber;
    }
    
    /**
     * 设置序列号
     *
     * @param string $serialNumber 序列号
     * @return self
     */
    public function setSerialNumber(string $serialNumber): self
    {
        $this->serialNumber = $serialNumber;
        return $this;
    }
    
    /**
     * 获取签名算法
     *
     * @return string|null
     */
    public function getSignatureAlgorithm(): ?string
    {
        return $this->signatureAlgorithm;
    }
    
    /**
     * 设置签名算法
     *
     * @param string $signatureAlgorithm 签名算法
     * @return self
     */
    public function setSignatureAlgorithm(string $signatureAlgorithm): self
    {
        $this->signatureAlgorithm = $signatureAlgorithm;
        return $this;
    }
    
    /**
     * 获取颁发者信息
     *
     * @return array|null
     */
    public function getIssuer(): ?array
    {
        return $this->issuer;
    }
    
    /**
     * 设置颁发者信息
     *
     * @param array $issuer 颁发者信息
     * @return self
     */
    public function setIssuer(array $issuer): self
    {
        $this->issuer = $issuer;
        return $this;
    }
    
    /**
     * 获取主题信息
     *
     * @return array|null
     */
    public function getSubject(): ?array
    {
        return $this->subject;
    }
    
    /**
     * 设置主题信息
     *
     * @param array $subject 主题信息
     * @return self
     */
    public function setSubject(array $subject): self
    {
        $this->subject = $subject;
        return $this;
    }
    
    /**
     * 获取证书有效期开始时间
     *
     * @return DateTimeImmutable|null
     */
    public function getNotBefore(): ?DateTimeImmutable
    {
        return $this->notBefore;
    }
    
    /**
     * 设置证书有效期开始时间
     *
     * @param DateTimeImmutable $notBefore 有效期开始时间
     * @return self
     */
    public function setNotBefore(DateTimeImmutable $notBefore): self
    {
        $this->notBefore = $notBefore;
        return $this;
    }
    
    /**
     * 获取证书有效期结束时间
     *
     * @return DateTimeImmutable|null
     */
    public function getNotAfter(): ?DateTimeImmutable
    {
        return $this->notAfter;
    }
    
    /**
     * 设置证书有效期结束时间
     *
     * @param DateTimeImmutable $notAfter 有效期结束时间
     * @return self
     */
    public function setNotAfter(DateTimeImmutable $notAfter): self
    {
        $this->notAfter = $notAfter;
        return $this;
    }
    
    /**
     * 获取公钥
     *
     * @return string|null
     */
    public function getPublicKey(): ?string
    {
        return $this->publicKey;
    }
    
    /**
     * 设置公钥
     *
     * @param string $publicKey 公钥
     * @return self
     */
    public function setPublicKey(string $publicKey): self
    {
        $this->publicKey = $publicKey;
        return $this;
    }
    
    /**
     * 检查证书是否在有效期内
     *
     * @return bool 如果证书在有效期内则返回true
     */
    public function isValid(): bool
    {
        if ($this->notBefore === null || $this->notAfter === null) {
            return false;
        }
        
        $now = new DateTimeImmutable();
        return $now >= $this->notBefore && $now <= $this->notAfter;
    }
} 