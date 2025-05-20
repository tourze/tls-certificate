<?php

declare(strict_types=1);

namespace Tourze\TLSCertificate\Revocation\CRL;

use DateTimeImmutable;
use Tourze\TLSCertificate\Certificate\X509Certificate;
use Tourze\TLSCertificate\Exception\CRLException;

/**
 * 证书撤销列表 - 表示完整的X.509 CRL
 */
class CertificateRevocationList
{
    /**
     * @var string 颁发者可分辨名称
     */
    private string $issuerDN;
    
    /**
     * @var DateTimeImmutable 最后更新时间
     */
    private DateTimeImmutable $thisUpdate;
    
    /**
     * @var DateTimeImmutable|null 下次更新时间
     */
    private ?DateTimeImmutable $nextUpdate;
    
    /**
     * @var array<string, CRLEntry> 撤销条目，按序列号索引
     */
    private array $revokedCertificates = [];
    
    /**
     * @var string CRL序列号
     */
    private string $crlNumber;
    
    /**
     * @var X509Certificate|null 颁发者证书
     */
    private ?X509Certificate $issuerCertificate = null;
    
    /**
     * @var string|null 签名算法
     */
    private ?string $signatureAlgorithm = null;
    
    /**
     * @var string|null 签名值
     */
    private ?string $signatureValue = null;
    
    /**
     * @var string|null 原始CRL数据
     */
    private ?string $rawData = null;
    
    /**
     * 构造函数
     *
     * @param string $issuerDN 颁发者可分辨名称
     * @param DateTimeImmutable $thisUpdate 最后更新时间
     * @param DateTimeImmutable|null $nextUpdate 下次更新时间
     * @param string $crlNumber CRL序列号
     * @param string|null $signatureAlgorithm 签名算法
     * @param string|null $signatureValue 签名值
     * @param string|null $rawData 原始CRL数据
     */
    public function __construct(
        string $issuerDN,
        DateTimeImmutable $thisUpdate,
        ?DateTimeImmutable $nextUpdate,
        string $crlNumber,
        ?string $signatureAlgorithm = null,
        ?string $signatureValue = null,
        ?string $rawData = null
    ) {
        $this->issuerDN = $issuerDN;
        $this->thisUpdate = $thisUpdate;
        $this->nextUpdate = $nextUpdate;
        $this->crlNumber = $crlNumber;
        $this->signatureAlgorithm = $signatureAlgorithm;
        $this->signatureValue = $signatureValue;
        $this->rawData = $rawData;
    }
    
    /**
     * 添加撤销条目
     *
     * @param CRLEntry $entry 撤销条目
     * @return $this
     */
    public function addRevokedCertificate(CRLEntry $entry): self
    {
        $this->revokedCertificates[$entry->getSerialNumber()] = $entry;
        return $this;
    }
    
    /**
     * 获取颁发者可分辨名称
     *
     * @return string
     */
    public function getIssuerDN(): string
    {
        return $this->issuerDN;
    }
    
    /**
     * 获取最后更新时间
     *
     * @return DateTimeImmutable
     */
    public function getThisUpdate(): DateTimeImmutable
    {
        return $this->thisUpdate;
    }
    
    /**
     * 获取下次更新时间
     *
     * @return DateTimeImmutable|null
     */
    public function getNextUpdate(): ?DateTimeImmutable
    {
        return $this->nextUpdate;
    }
    
    /**
     * 获取所有撤销条目
     *
     * @return array<string, CRLEntry>
     */
    public function getRevokedCertificates(): array
    {
        return $this->revokedCertificates;
    }
    
    /**
     * 获取CRL序列号
     *
     * @return string
     */
    public function getCRLNumber(): string
    {
        return $this->crlNumber;
    }
    
    /**
     * 设置颁发者证书
     *
     * @param X509Certificate $certificate 颁发者证书
     * @return $this
     */
    public function setIssuerCertificate(X509Certificate $certificate): self
    {
        // 验证证书主题是否与CRL颁发者匹配
        if ($certificate->getSubjectDN() !== $this->issuerDN) {
            throw new CRLException('颁发者证书主题与CRL颁发者不匹配');
        }
        
        $this->issuerCertificate = $certificate;
        return $this;
    }
    
    /**
     * 获取颁发者证书
     *
     * @return X509Certificate|null
     */
    public function getIssuerCertificate(): ?X509Certificate
    {
        return $this->issuerCertificate;
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
     * 获取签名值
     *
     * @return string|null
     */
    public function getSignatureValue(): ?string
    {
        return $this->signatureValue;
    }
    
    /**
     * 获取原始CRL数据
     *
     * @return string|null
     */
    public function getRawData(): ?string
    {
        return $this->rawData;
    }
    
    /**
     * 检查CRL是否已过期
     *
     * @return bool 如果CRL已过期则返回true
     */
    public function isExpired(): bool
    {
        if ($this->nextUpdate === null) {
            // 如果没有指定nextUpdate，保守认为已过期
            return true;
        }
        
        return new DateTimeImmutable() > $this->nextUpdate;
    }
    
    /**
     * 检查证书是否已被撤销
     *
     * @param string $serialNumber 要检查的证书序列号
     * @return bool 如果证书已被撤销则返回true
     */
    public function isRevoked(string $serialNumber): bool
    {
        return isset($this->revokedCertificates[$serialNumber]);
    }
    
    /**
     * 获取证书的撤销条目
     *
     * @param string $serialNumber 要获取的证书序列号
     * @return CRLEntry|null 如果证书已被撤销则返回撤销条目，否则返回null
     */
    public function getRevokedCertificate(string $serialNumber): ?CRLEntry
    {
        return $this->revokedCertificates[$serialNumber] ?? null;
    }
} 