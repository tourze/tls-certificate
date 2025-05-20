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
     * @var string|null 主题专有名称
     */
    private ?string $subjectDN = null;
    
        /**     * @var string|null 颁发者专有名称     */    private ?string $issuerDN = null;        /**     * @var string|null 公钥的DER编码     */    private ?string $publicKeyDER = null;
    
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
     * @return string|null
     */
    public function getSubjectDN(): ?string
    {
        return $this->subjectDN;
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
     * @return string|null
     */
    public function getIssuerDN(): ?string
    {
        return $this->issuerDN;
    }
    
        /**     * 设置颁发者专有名称(DN)     *     * @param string $issuerDN 颁发者专有名称     * @return self     */    public function setIssuerDN(string $issuerDN): self    {        $this->issuerDN = $issuerDN;        return $this;    }        /**     * 获取公钥的DER编码     *     * @return string|null     */    public function getPublicKeyDER(): ?string    {        return $this->publicKeyDER;    }        /**     * 设置公钥的DER编码     *     * @param string $publicKeyDER 公钥的DER编码     * @return self     */    public function setPublicKeyDER(string $publicKeyDER): self    {        $this->publicKeyDER = $publicKeyDER;        return $this;    }
}
