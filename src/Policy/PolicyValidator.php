<?php

declare(strict_types=1);

namespace Tourze\TLSCertificate\Policy;

use Tourze\TLSCertificate\Certificate\X509Certificate;
use Tourze\TLSCertificate\Chain\CertificateChain;
use Tourze\TLSCertificate\Exception\CertificateValidationException;
use Tourze\TLSCertificate\Validator\ValidationResult;

/**
 * 策略验证器 - 验证证书策略约束
 */
class PolicyValidator
{
    /**
     * @var array 期望的策略OID列表
     */
    private array $expectedPolicies = [];
    
    /**
     * @var bool 是否需要明确的策略
     */
    private bool $requireExplicitPolicy = true;
    
    /**
     * @var bool 是否需要策略映射
     */
    private bool $requirePolicyMapping = false;
    
    /**
     * 构造函数
     */
    public function __construct()
    {
    }
    
    /**
     * 添加期望的策略
     *
     * @param string $policyOid 策略OID
     * @return $this
     */
    public function addExpectedPolicy(string $policyOid): self
    {
        $this->expectedPolicies[] = $policyOid;
        return $this;
    }
    
    /**
     * 设置是否需要明确的策略
     *
     * @param bool $requireExplicitPolicy
     * @return $this
     */
    public function setRequireExplicitPolicy(bool $requireExplicitPolicy): self
    {
        $this->requireExplicitPolicy = $requireExplicitPolicy;
        return $this;
    }
    
    /**
     * 设置是否需要策略映射
     *
     * @param bool $requirePolicyMapping
     * @return $this
     */
    public function setRequirePolicyMapping(bool $requirePolicyMapping): self
    {
        $this->requirePolicyMapping = $requirePolicyMapping;
        return $this;
    }
    
    /**
     * 验证证书链的策略约束
     *
     * @param CertificateChain $chain 要验证的证书链
     * @param ValidationResult $result 验证结果
     * @return bool 如果验证通过则返回true
     */
    public function validate(CertificateChain $chain, ValidationResult $result): bool
    {
        // 如果链为空，无法验证
        if ($chain->isEmpty()) {
            $result->addError('无法验证空的证书链');
            return false;
        }
        
        try {
            // 获取叶子证书
            $leafCertificate = $chain->getLeafCertificate();
            
            // 如果没有期望的策略且不需要明确策略，则直接通过
            if (empty($this->expectedPolicies) && !$this->requireExplicitPolicy) {
                $result->addInfo('未设置策略约束，跳过策略验证');
                return true;
            }
            
            // 获取叶子证书的策略
            $leafPolicies = $this->getCertificatePolicies($leafCertificate);
            
            // 如果需要明确策略但证书没有策略，则验证失败
            if ($this->requireExplicitPolicy && empty($leafPolicies)) {
                $result->addError('证书没有策略扩展，但要求明确的策略');
                return false;
            }
            
            // 验证策略匹配
            if (!empty($this->expectedPolicies)) {
                $matchFound = false;
                
                foreach ($leafPolicies as $policy) {
                    // 检查是否为anyPolicy
                    if ($policy->getPolicyOid() === CertificatePolicy::ANY_POLICY) {
                        $matchFound = true;
                        break;
                    }
                    
                    // 检查是否匹配期望的策略
                    foreach ($this->expectedPolicies as $expectedPolicyOid) {
                        if ($policy->getPolicyOid() === $expectedPolicyOid) {
                            $matchFound = true;
                            break 2;
                        }
                    }
                }
                
                if (!$matchFound) {
                    $result->addError('证书策略不匹配期望的策略');
                    return false;
                }
            }
            
            // 如果要求策略映射，则需要验证整个链的策略一致性
            if ($this->requirePolicyMapping && $chain->getLength() > 1) {
                if (!$this->validatePolicyMapping($chain, $result)) {
                    return false;
                }
            }
            
            $result->addInfo('证书策略验证通过');
            return true;
            
        } catch (CertificateValidationException $e) {
            $result->addError('策略验证失败: ' . $e->getMessage());
            return false;
        } catch (\Exception $e) {
            $result->addError('策略验证时发生未预期错误: ' . $e->getMessage());
            return false;
        }
    }
    
    /**
     * 从证书中提取证书策略
     *
     * @param X509Certificate $certificate
     * @return array<CertificatePolicy>
     */
    private function getCertificatePolicies(X509Certificate $certificate): array
    {
        // 此处应从证书的扩展中提取策略
        // 简化版实现，假设已经可以从证书中获取策略OID
        $policies = [];
        
        // 从证书中获取策略OID
        $policyOids = $certificate->getCertificatePolicies();
        
        if (empty($policyOids)) {
            return [];
        }
        
        foreach ($policyOids as $policyOid) {
            $policies[] = new CertificatePolicy($policyOid);
        }
        
        return $policies;
    }
    
    /**
     * 验证策略映射
     *
     * @param CertificateChain $chain 证书链
     * @param ValidationResult $result 验证结果
     * @return bool 如果验证通过则返回true
     */
    private function validatePolicyMapping(CertificateChain $chain, ValidationResult $result): bool
    {
        $certificates = $chain->getCertificates();
        
        // 检查每个证书的策略是否与下一个证书的策略兼容
        for ($i = 0; $i < count($certificates) - 1; $i++) {
            $current = $certificates[$i];
            $issuer = $certificates[$i + 1];
            
            $currentPolicies = $this->getCertificatePolicies($current);
            $issuerPolicies = $this->getCertificatePolicies($issuer);
            
            // 如果当前证书没有策略，跳过
            if (empty($currentPolicies)) {
                continue;
            }
            
            // 如果颁发者没有策略，但当前证书有策略，则不匹配
            if (empty($issuerPolicies)) {
                $result->addError('证书链中的策略不一致：颁发者没有策略');
                return false;
            }
            
            // 检查每个当前证书策略是否与颁发者的策略兼容
            foreach ($currentPolicies as $currentPolicy) {
                $compatible = false;
                
                foreach ($issuerPolicies as $issuerPolicy) {
                    if ($currentPolicy->matches($issuerPolicy)) {
                        $compatible = true;
                        break;
                    }
                }
                
                if (!$compatible) {
                    $result->addError('证书链中的策略不一致：策略 ' . $currentPolicy->getPolicyOid() . ' 不兼容');
                    return false;
                }
            }
        }
        
        $result->addInfo('证书链的策略映射验证通过');
        return true;
    }
} 