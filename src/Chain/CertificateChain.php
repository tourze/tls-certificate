<?php

declare(strict_types=1);

namespace Tourze\TLSCertificate\Chain;

use Tourze\TLSCertificate\Certificate\X509Certificate;
use Tourze\TLSCertificate\Exception\CertificateValidationException;

/**
 * 证书链 - 管理X.509证书链
 */
class CertificateChain
{
    /**
     * @var X509Certificate[] 证书链（从叶子证书到根证书的顺序）
     */
    private array $certificates = [];
    
    /**
     * 构造函数
     *
     * @param X509Certificate[] $certificates 证书链，从叶子证书到根证书排列
     */
    public function __construct(array $certificates = [])
    {
        foreach ($certificates as $certificate) {
            $this->addCertificate($certificate);
        }
    }
    
    /**
     * 添加证书到链中
     *
     * @param X509Certificate $certificate 要添加的证书
     * @return $this
     */
    public function addCertificate(X509Certificate $certificate): self
    {
        $this->certificates[] = $certificate;
        return $this;
    }
    
    /**
     * 获取证书链
     *
     * @return X509Certificate[] 证书数组
     */
    public function getCertificates(): array
    {
        return $this->certificates;
    }
    
    /**
     * 获取叶子证书（链中的第一个证书）
     *
     * @return X509Certificate|null 叶子证书，如果链为空则返回null
     */
    public function getLeafCertificate(): ?X509Certificate
    {
        return !empty($this->certificates) ? $this->certificates[0] : null;
    }
    
    /**
     * 获取根证书（链中的最后一个证书）
     *
     * @return X509Certificate|null 根证书，如果链为空则返回null
     */
    public function getRootCertificate(): ?X509Certificate
    {
        return !empty($this->certificates) ? $this->certificates[count($this->certificates) - 1] : null;
    }
    
    /**
     * 检查链是否为空
     *
     * @return bool 如果链为空则返回true
     */
    public function isEmpty(): bool
    {
        return empty($this->certificates);
    }
    
    /**
     * 获取链长度
     *
     * @return int 证书链中的证书数量
     */
    public function getLength(): int
    {
        return count($this->certificates);
    }
    
    /**
     * 验证链的完整性
     *
     * @param bool $verifySignatures 是否验证证书签名
     * @return bool 如果链完整则返回true
     * @throws CertificateValidationException 如果链不完整
     */
    public function verifyChainIntegrity(bool $verifySignatures = true): bool
    {
        if ($this->isEmpty()) {
            throw new CertificateValidationException('证书链为空');
        }
        
        // 检查每个证书是否正确链接到其颁发者
        for ($i = 0; $i < count($this->certificates) - 1; $i++) {
            $current = $this->certificates[$i];
            $issuer = $this->certificates[$i + 1];
            
            // 检查颁发者名称
            if ($current->getIssuerDN() !== $issuer->getSubjectDN()) {
                throw CertificateValidationException::issuerCertificateNotFound(
                    $current->getIssuerDN(),
                    $current->getSubjectDN(),
                    $current->getSerialNumber()
                );
            }
            
            // 验证签名
            if ($verifySignatures) {
                // TODO: 实现签名验证
                // 此处需要调用签名验证逻辑
            }
        }
        
        // 检查根证书是否为自签名
        $root = $this->getRootCertificate();
        if ($root && $root->getIssuerDN() !== $root->getSubjectDN()) {
            throw new CertificateValidationException('证书链的根证书不是自签名的');
        }
        
        return true;
    }
    
    /**
     * 从未排序的证书集合构建证书链
     *
     * @param X509Certificate $leafCertificate 叶子证书
     * @param X509Certificate[] $certificates 可用于构建链的证书集合
     * @return self 构建的证书链
     * @throws CertificateValidationException 如果无法构建完整的链
     */
    public static function buildFromCertificates(X509Certificate $leafCertificate, array $certificates): self
    {
        $chain = new self([$leafCertificate]);
        $currentCertificate = $leafCertificate;
        
        // 防止无限循环
        $maxChainLength = 10;
        
        while (count($chain->getCertificates()) < $maxChainLength) {
            // 如果当前证书是自签名的，则链已完成
            if ($currentCertificate->getIssuerDN() === $currentCertificate->getSubjectDN()) {
                break;
            }
            
            // 查找颁发者证书
            $issuerFound = false;
            foreach ($certificates as $certificate) {
                // 跳过已在链中的证书
                if (self::containsCertificate($chain->getCertificates(), $certificate)) {
                    continue;
                }
                
                // 检查是否是颁发者
                if ($certificate->getSubjectDN() === $currentCertificate->getIssuerDN()) {
                    $chain->addCertificate($certificate);
                    $currentCertificate = $certificate;
                    $issuerFound = true;
                    break;
                }
            }
            
            // 如果找不到颁发者，则链不完整
            if (!$issuerFound) {
                throw CertificateValidationException::incompleteCertificateChain(
                    $leafCertificate->getSubjectDN(),
                    $leafCertificate->getSerialNumber()
                );
            }
        }
        
        return $chain;
    }
    
    /**
     * 检查证书是否已在列表中
     *
     * @param X509Certificate[] $certificates 证书列表
     * @param X509Certificate $certificate 要检查的证书
     * @return bool 如果证书已在列表中则返回true
     */
    private static function containsCertificate(array $certificates, X509Certificate $certificate): bool
    {
        foreach ($certificates as $cert) {
            if ($cert->getSerialNumber() === $certificate->getSerialNumber()) {
                return true;
            }
        }
        
        return false;
    }
} 