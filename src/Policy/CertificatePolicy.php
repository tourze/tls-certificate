<?php

declare(strict_types=1);

namespace Tourze\TLSCertificate\Policy;

/**
 * 证书策略 - 管理X.509证书策略相关功能
 */
class CertificatePolicy
{
    /**
     * @var string 策略OID
     */
    private string $policyOid;
    
    /**
     * @var string|null 策略限定符
     */
    private ?string $qualifier = null;
    
    /**
     * @var string|null 策略信息URI
     */
    private ?string $policyInfoUri = null;
    
    /**
     * @var string|null 策略显示文本
     */
    private ?string $displayText = null;
    
    /**
     * 构造函数
     *
     * @param string $policyOid 策略OID
     * @param string|null $qualifier 策略限定符
     * @param string|null $policyInfoUri 策略信息URI
     * @param string|null $displayText 策略显示文本
     */
    public function __construct(
        string $policyOid,
        ?string $qualifier = null,
        ?string $policyInfoUri = null,
        ?string $displayText = null
    ) {
        $this->policyOid = $policyOid;
        $this->qualifier = $qualifier;
        $this->policyInfoUri = $policyInfoUri;
        $this->displayText = $displayText;
    }
    
    /**
     * 获取策略OID
     *
     * @return string
     */
    public function getPolicyOid(): string
    {
        return $this->policyOid;
    }
    
    /**
     * 获取策略限定符
     *
     * @return string|null
     */
    public function getQualifier(): ?string
    {
        return $this->qualifier;
    }
    
    /**
     * 获取策略信息URI
     *
     * @return string|null
     */
    public function getPolicyInfoUri(): ?string
    {
        return $this->policyInfoUri;
    }
    
    /**
     * 获取策略显示文本
     *
     * @return string|null
     */
    public function getDisplayText(): ?string
    {
        return $this->displayText;
    }
    
    /**
     * 检查策略是否匹配
     *
     * @param CertificatePolicy $other 要比较的其他策略
     * @return bool 如果策略匹配则返回true
     */
    public function matches(CertificatePolicy $other): bool
    {
        // 检查OID是否相同
        if ($this->policyOid === $other->getPolicyOid()) {
            return true;
        }
        
        // 检查是否为anyPolicy
        if ($this->policyOid === self::ANY_POLICY || $other->getPolicyOid() === self::ANY_POLICY) {
            return true;
        }
        
        return false;
    }
    
    /**
     * 标准的任意策略OID
     */
    public const ANY_POLICY = '2.5.29.32.0';
    
    /**
     * 创建任意策略
     *
     * @return self
     */
    public static function createAnyPolicy(): self
    {
        return new self(self::ANY_POLICY);
    }
} 