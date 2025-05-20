<?php

declare(strict_types=1);

namespace Tourze\TLSCertificate\Certificate;

/**
 * X.509证书类
 * 
 * 表示一个标准X.509格式的证书，包含所有证书字段和验证方法
 */
class X509Certificate extends Certificate
{
    /**
     * @var array|null 扩展字段
     */
    private ?array $extensions = null;
    
    /**
     * @var string|null 签名
     */
    private ?string $signature = null;
    
    /**
     * @var array|null 证书分发点
     */
    private ?array $crlDistributionPoints = null;
    
    /**
     * @var string|null OCSP响应器URL
     */
    private ?string $ocspResponderUrl = null;
    
    /**
     * @var array|null OCSP URLs列表
     */
    private ?array $ocspURLs = null;
    
    /**
     * @var string|null 主题专有名称
     */
    private ?string $subjectDN = null;
    
    /**
     * @var string|null 颁发者专有名称
     */
    private ?string $issuerDN = null;
    
    /**
     * @var string|null 公钥的DER编码
     */
    private ?string $publicKeyDER = null;
    
    /**
     * 获取证书扩展字段
     *
     * @return array|null
     */
    public function getExtensions(): ?array
    {
        return $this->extensions;
    }
    
    /**
     * 设置证书扩展字段
     *
     * @param array $extensions 扩展字段
     * @return self
     */
    public function setExtensions(array $extensions): self
    {
        $this->extensions = $extensions;
        return $this;
    }
    
    /**
     * 获取证书签名
     *
     * @return string|null
     */
    public function getSignature(): ?string
    {
        return $this->signature;
    }
    
    /**
     * 设置证书签名
     *
     * @param string $signature 签名数据
     * @return self
     */
    public function setSignature(string $signature): self
    {
        $this->signature = $signature;
        return $this;
    }
    
    /**
     * 获取CRL分发点
     *
     * @return array|null
     */
    public function getCRLDistributionPoints(): ?array
    {
        return $this->crlDistributionPoints;
    }
    
    /**
     * 设置CRL分发点
     *
     * @param array $crlDistributionPoints CRL分发点
     * @return self
     */
    public function setCRLDistributionPoints(array $crlDistributionPoints): self
    {
        $this->crlDistributionPoints = $crlDistributionPoints;
        return $this;
    }
    
    /**
     * 获取OCSP响应器URL
     *
     * @return string|null
     */
    public function getOCSPResponderUrl(): ?string
    {
        return $this->ocspResponderUrl;
    }
    
    /**
     * 设置OCSP响应器URL
     *
     * @param string $ocspResponderUrl OCSP响应器URL
     * @return self
     */
    public function setOCSPResponderUrl(string $ocspResponderUrl): self
    {
        $this->ocspResponderUrl = $ocspResponderUrl;
        return $this;
    }
    
    /**
     * 获取OCSP URLs列表
     * 
     * @return array 可用的OCSP URL列表
     */
    public function getOCSPURLs(): array
    {
        if ($this->ocspURLs === null) {
            // 初始化为空数组
            $this->ocspURLs = [];
            
            // 如果有单个OCSP响应器URL，添加到列表中
            if ($this->ocspResponderUrl !== null) {
                $this->ocspURLs[] = $this->ocspResponderUrl;
            }
            
            // 查找证书扩展中的OCSP URLs
            // OID: 1.3.6.1.5.5.7.1.1 = Authority Information Access
            if ($this->hasExtension('1.3.6.1.5.5.7.1.1')) {
                $aia = $this->getExtension('1.3.6.1.5.5.7.1.1');
                
                // 解析AIA扩展中的OCSP URLs
                // 这里简化实现，实际应该根据ASN.1结构解析
                if (is_array($aia) && isset($aia['ocsp'])) {
                    foreach ($aia['ocsp'] as $ocspUrl) {
                        if (!in_array($ocspUrl, $this->ocspURLs)) {
                            $this->ocspURLs[] = $ocspUrl;
                        }
                    }
                }
            }
        }
        
        return $this->ocspURLs;
    }
    
    /**
     * 设置OCSP URLs列表
     * 
     * @param array $ocspURLs OCSP URLs列表
     * @return self
     */
    public function setOCSPURLs(array $ocspURLs): self
    {
        $this->ocspURLs = $ocspURLs;
        return $this;
    }
    
    /**
     * 检查证书是否具有指定的扩展
     *
     * @param string $oid 扩展OID
     * @return bool
     */
    public function hasExtension(string $oid): bool
    {
        if ($this->extensions === null) {
            return false;
        }
        
        return isset($this->extensions[$oid]);
    }
    
    /**
     * 获取指定的扩展字段
     *
     * @param string $oid 扩展OID
     * @return mixed|null
     */
    public function getExtension(string $oid): mixed
    {
        if (!$this->hasExtension($oid)) {
            return null;
        }
        
        return $this->extensions[$oid];
    }
    
    /**
     * 获取主题专有名称(DN)
     *
     * @param bool $derFormat 是否返回DER编码格式
     * @return string|null
     */
    public function getSubjectDN(bool $derFormat = false): ?string
    {
        if ($derFormat) {
            return $this->getSubjectDNDER();
        }
        return $this->subjectDN;
    }
    
    /**
     * 获取主题专有名称的DER编码
     * 
     * @return string DER编码的主题DN
     */
    public function getSubjectDNDER(): string
    {
        // 简化实现，实际应该将文本格式的DN转换为DER编码
        // 这里假设已经有DER编码数据或者使用占位符
        return $this->subjectDN ?? 'subject-dn-der-placeholder';
    }
    
    /**
     * 设置主题专有名称(DN)
     *
     * @param string $subjectDN 主题专有名称
     * @return self
     */
    public function setSubjectDN(string $subjectDN): self
    {
        $this->subjectDN = $subjectDN;
        return $this;
    }
    
    /**
     * 获取颁发者专有名称(DN)
     *
     * @param bool $derFormat 是否返回DER编码格式
     * @return string|null
     */
    public function getIssuerDN(bool $derFormat = false): ?string
    {
        if ($derFormat) {
            return $this->getIssuerDNDER();
        }
        return $this->issuerDN;
    }
    
    /**
     * 获取颁发者专有名称的DER编码
     * 
     * @return string DER编码的颁发者DN
     */
    public function getIssuerDNDER(): string
    {
        // 简化实现，实际应该将文本格式的DN转换为DER编码
        // 这里假设已经有DER编码数据或者使用占位符
        return $this->issuerDN ?? 'issuer-dn-der-placeholder';
    }
    
    /**
     * 设置颁发者专有名称(DN)
     *
     * @param string $issuerDN 颁发者专有名称
     * @return self
     */
    public function setIssuerDN(string $issuerDN): self
    {
        $this->issuerDN = $issuerDN;
        return $this;
    }
    
    /**
     * 获取公钥的DER编码
     *
     * @return string|null
     */
    public function getPublicKeyDER(): ?string
    {
        return $this->publicKeyDER;
    }
    
    /**
     * 设置公钥的DER编码
     *
     * @param string $publicKeyDER 公钥的DER编码
     * @return self
     */
    public function setPublicKeyDER(string $publicKeyDER): self
    {
        $this->publicKeyDER = $publicKeyDER;
        return $this;
    }
    
    /**
     * 获取证书的PEM格式表示
     * 
     * @return string PEM格式的证书
     */
    public function toPEM(): string
    {
        // 简化实现，返回一个基本的PEM结构
        return "-----BEGIN CERTIFICATE-----\n" . 
               "MIIDXTCC... (certificate data)...\n" . 
               "-----END CERTIFICATE-----";
    }
}
