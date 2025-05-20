<?php

declare(strict_types=1);

namespace Tourze\TLSCertificate\Validator;

/**
 * 证书验证选项 - 配置证书验证过程中的行为
 */
class ValidationOptions
{
    /**
     * @var bool 是否验证证书链
     */
    private bool $validateCertificateChain = true;
    
    /**
     * @var bool 是否验证密钥用途
     */
    private bool $validateKeyUsage = true;
    
    /**
     * @var bool 是否验证扩展密钥用途
     */
    private bool $validateExtendedKeyUsage = true;
    
    /**
     * @var bool 是否需要完整的证书链
     */
    private bool $requireCompleteCertificateChain = true;
    
    /**
     * @var bool 是否允许自签名证书
     */
    private bool $allowSelfSignedCertificates = false;
    
    /**
     * @var array 预期的密钥用途
     */
    private array $expectedKeyUsage = [];
    
    /**
     * @var array 预期的扩展密钥用途
     */
    private array $expectedExtendedKeyUsage = [];
    
    /**
     * @var bool 是否验证证书撤销状态
     */
    private bool $checkRevocation = false;
    
    /**
     * @var bool 是否验证证书主题替代名称
     */
    private bool $validateSubjectAlternativeName = true;
    
    /**
     * @var string|null 预期的主机名（用于SAN验证）
     */
    private ?string $expectedHostname = null;
    
    /**
     * 构造函数
     */
    public function __construct()
    {
    }
    
    /**
     * 设置是否验证证书链
     *
     * @param bool $validateCertificateChain
     * @return $this
     */
    public function setValidateCertificateChain(bool $validateCertificateChain): self
    {
        $this->validateCertificateChain = $validateCertificateChain;
        return $this;
    }
    
    /**
     * 获取是否验证证书链
     *
     * @return bool
     */
    public function isValidateCertificateChain(): bool
    {
        return $this->validateCertificateChain;
    }
    
    /**
     * 设置是否验证密钥用途
     *
     * @param bool $validateKeyUsage
     * @return $this
     */
    public function setValidateKeyUsage(bool $validateKeyUsage): self
    {
        $this->validateKeyUsage = $validateKeyUsage;
        return $this;
    }
    
    /**
     * 获取是否验证密钥用途
     *
     * @return bool
     */
    public function isValidateKeyUsage(): bool
    {
        return $this->validateKeyUsage;
    }
    
    /**
     * 设置是否验证扩展密钥用途
     *
     * @param bool $validateExtendedKeyUsage
     * @return $this
     */
    public function setValidateExtendedKeyUsage(bool $validateExtendedKeyUsage): self
    {
        $this->validateExtendedKeyUsage = $validateExtendedKeyUsage;
        return $this;
    }
    
    /**
     * 获取是否验证扩展密钥用途
     *
     * @return bool
     */
    public function isValidateExtendedKeyUsage(): bool
    {
        return $this->validateExtendedKeyUsage;
    }
    
    /**
     * 设置是否需要完整的证书链
     *
     * @param bool $requireCompleteCertificateChain
     * @return $this
     */
    public function setRequireCompleteCertificateChain(bool $requireCompleteCertificateChain): self
    {
        $this->requireCompleteCertificateChain = $requireCompleteCertificateChain;
        return $this;
    }
    
    /**
     * 获取是否需要完整的证书链
     *
     * @return bool
     */
    public function isRequireCompleteCertificateChain(): bool
    {
        return $this->requireCompleteCertificateChain;
    }
    
    /**
     * 设置是否允许自签名证书
     *
     * @param bool $allowSelfSignedCertificates
     * @return $this
     */
    public function setAllowSelfSignedCertificates(bool $allowSelfSignedCertificates): self
    {
        $this->allowSelfSignedCertificates = $allowSelfSignedCertificates;
        return $this;
    }
    
    /**
     * 获取是否允许自签名证书
     *
     * @return bool
     */
    public function isAllowSelfSignedCertificates(): bool
    {
        return $this->allowSelfSignedCertificates;
    }
    
    /**
     * 设置预期的密钥用途
     *
     * @param array $expectedKeyUsage
     * @return $this
     */
    public function setExpectedKeyUsage(array $expectedKeyUsage): self
    {
        $this->expectedKeyUsage = $expectedKeyUsage;
        return $this;
    }
    
    /**
     * 获取预期的密钥用途
     *
     * @return array
     */
    public function getExpectedKeyUsage(): array
    {
        return $this->expectedKeyUsage;
    }
    
    /**
     * 设置预期的扩展密钥用途
     *
     * @param array $expectedExtendedKeyUsage
     * @return $this
     */
    public function setExpectedExtendedKeyUsage(array $expectedExtendedKeyUsage): self
    {
        $this->expectedExtendedKeyUsage = $expectedExtendedKeyUsage;
        return $this;
    }
    
    /**
     * 获取预期的扩展密钥用途
     *
     * @return array
     */
    public function getExpectedExtendedKeyUsage(): array
    {
        return $this->expectedExtendedKeyUsage;
    }
    
    /**
     * 设置是否验证证书撤销状态
     *
     * @param bool $checkRevocation
     * @return $this
     */
    public function setCheckRevocation(bool $checkRevocation): self
    {
        $this->checkRevocation = $checkRevocation;
        return $this;
    }
    
    /**
     * 获取是否验证证书撤销状态
     *
     * @return bool
     */
    public function isCheckRevocation(): bool
    {
        return $this->checkRevocation;
    }
    
    /**
     * 设置是否验证证书主题替代名称
     *
     * @param bool $validateSubjectAlternativeName
     * @return $this
     */
    public function setValidateSubjectAlternativeName(bool $validateSubjectAlternativeName): self
    {
        $this->validateSubjectAlternativeName = $validateSubjectAlternativeName;
        return $this;
    }
    
    /**
     * 获取是否验证证书主题替代名称
     *
     * @return bool
     */
    public function isValidateSubjectAlternativeName(): bool
    {
        return $this->validateSubjectAlternativeName;
    }
    
    /**
     * 设置预期的主机名
     *
     * @param string|null $expectedHostname
     * @return $this
     */
    public function setExpectedHostname(?string $expectedHostname): self
    {
        $this->expectedHostname = $expectedHostname;
        return $this;
    }
    
    /**
     * 获取预期的主机名
     *
     * @return string|null
     */
    public function getExpectedHostname(): ?string
    {
        return $this->expectedHostname;
    }
} 