<?php

declare(strict_types=1);

namespace Tourze\TLSCertificate\CrossSign;

use Tourze\TLSCertificate\Certificate\X509Certificate;
use Tourze\TLSCertificate\Exception\CertificateValidationException;

/**
 * 交叉签名证书 - 处理交叉签名的X.509证书
 */
class CrossSignedCertificate
{
    /**
     * @var X509Certificate 主要证书
     */
    private X509Certificate $primaryCertificate;
    
    /**
     * @var X509Certificate[] 交叉签名证书列表
     */
    private array $crossSignedCertificates = [];
    
    /**
     * 构造函数
     *
     * @param X509Certificate $primaryCertificate 主要证书
     * @param array $crossSignedCertificates 交叉签名证书列表
     */
    public function __construct(
        X509Certificate $primaryCertificate,
        array $crossSignedCertificates = []
    ) {
        $this->primaryCertificate = $primaryCertificate;
        
        foreach ($crossSignedCertificates as $cert) {
            $this->addCrossSignedCertificate($cert);
        }
    }
    
    /**
     * 添加交叉签名证书
     *
     * @param X509Certificate $certificate 交叉签名证书
     * @return $this
     * @throws CertificateValidationException 如果证书不是有效的交叉签名证书
     */
    public function addCrossSignedCertificate(X509Certificate $certificate): self
    {
        // 验证是否为有效的交叉签名证书
        $this->validateCrossSignedCertificate($certificate);
        
        $this->crossSignedCertificates[] = $certificate;
        return $this;
    }
    
    /**
     * 获取主要证书
     *
     * @return X509Certificate
     */
    public function getPrimaryCertificate(): X509Certificate
    {
        return $this->primaryCertificate;
    }
    
    /**
     * 获取交叉签名证书列表
     *
     * @return X509Certificate[]
     */
    public function getCrossSignedCertificates(): array
    {
        return $this->crossSignedCertificates;
    }
    
    /**
     * 根据颁发者获取交叉签名证书
     *
     * @param string $issuerDN 颁发者DN
     * @return X509Certificate|null 匹配的交叉签名证书，如果未找到则返回null
     */
    public function getCrossSignedCertificateByIssuer(string $issuerDN): ?X509Certificate
    {
        foreach ($this->crossSignedCertificates as $cert) {
            if ($cert->getIssuerDN() === $issuerDN) {
                return $cert;
            }
        }
        
        // 如果主证书的颁发者匹配，返回主证书
        if ($this->primaryCertificate->getIssuerDN() === $issuerDN) {
            return $this->primaryCertificate;
        }
        
        return null;
    }
    
    /**
     * 检查是否有来自指定颁发者的交叉签名证书
     *
     * @param string $issuerDN 颁发者DN
     * @return bool 如果存在则返回true
     */
    public function hasCrossSignedCertificateFromIssuer(string $issuerDN): bool
    {
        return $this->getCrossSignedCertificateByIssuer($issuerDN) !== null;
    }
    
    /**
     * 验证交叉签名证书是否有效
     *
     * @param X509Certificate $certificate 要验证的证书
     * @throws CertificateValidationException 如果不是有效的交叉签名证书
     */
    private function validateCrossSignedCertificate(X509Certificate $certificate): void
    {
        // 检查公钥是否相同
        if ($certificate->getPublicKey() !== $this->primaryCertificate->getPublicKey()) {
            throw new CertificateValidationException('交叉签名证书的公钥与主证书不匹配');
        }
        
        // 检查主题是否相同
        if ($certificate->getSubjectDN() !== $this->primaryCertificate->getSubjectDN()) {
            throw new CertificateValidationException('交叉签名证书的主题与主证书不匹配');
        }
        
        // 检查颁发者是否不同
        if ($certificate->getIssuerDN() === $this->primaryCertificate->getIssuerDN()) {
            throw new CertificateValidationException('交叉签名证书的颁发者与主证书相同，不是有效的交叉签名');
        }
    }
    
    /**
     * 从证书列表中检测和创建交叉签名证书组
     *
     * @param array $certificates 证书列表
     * @return array<string, CrossSignedCertificate> 交叉签名证书组，键为公钥标识符
     */
    public static function detectFromCertificates(array $certificates): array
    {
        $groups = [];
        $tempGroups = [];
        
        // 按公钥分组
        foreach ($certificates as $cert) {
            $publicKey = $cert->getPublicKey();
            $subjectDN = $cert->getSubjectDN();
            $key = $publicKey . '|' . $subjectDN;
            
            if (!isset($tempGroups[$key])) {
                $tempGroups[$key] = [];
            }
            
            $tempGroups[$key][] = $cert;
        }
        
        // 创建交叉签名证书组
        foreach ($tempGroups as $key => $certs) {
            if (count($certs) > 1) {
                // 有多个具有相同公钥和主题的证书，可能是交叉签名
                // 使用第一个作为主证书
                $primary = array_shift($certs);
                $groups[$key] = new self($primary, $certs);
            } elseif (count($certs) === 1) {
                // 只有一个证书，作为主证书
                $groups[$key] = new self($certs[0]);
            }
        }
        
        return $groups;
    }
} 