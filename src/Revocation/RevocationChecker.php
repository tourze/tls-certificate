<?php

declare(strict_types=1);

namespace Tourze\TLSCertificate\Revocation;

use Tourze\TLSCertificate\Certificate\X509Certificate;
use Tourze\TLSCertificate\Exception\RevocationCheckException;
use Tourze\TLSCertificate\Revocation\CRL\CRLValidator;
use Tourze\TLSCertificate\Revocation\OCSP\OCSPClient;

/**
 * 撤销检查器，实现不同的撤销检查策略
 */
class RevocationChecker implements RevocationCheckerInterface
{
    /**
     * 撤销检查策略
     */
    private RevocationPolicy $policy;
    
    /**
     * OCSP客户端
     */
    private ?OCSPClient $ocspClient;
    
    /**
     * CRL验证器
     */
    private ?CRLValidator $crlValidator;
    
    /**
     * 上次检查结果
     */
    private array $lastCheckStatus = [];
    
    /**
     * 构造函数
     * 
     * @param RevocationPolicy $policy 撤销检查策略
     * @param ?OCSPClient $ocspClient OCSP客户端
     * @param ?CRLValidator $crlValidator CRL验证器
     */
    public function __construct(
        RevocationPolicy $policy = RevocationPolicy::OCSP_PREFERRED,
        ?OCSPClient $ocspClient = null,
        ?CRLValidator $crlValidator = null
    ) {
        $this->policy = $policy;
        $this->ocspClient = $ocspClient;
        $this->crlValidator = $crlValidator;
        
        // 根据策略，确保必要的组件已初始化
        if ($this->requiresOCSP() && $this->ocspClient === null) {
            $this->ocspClient = new OCSPClient();
        }
        
        if ($this->requiresCRL() && $this->crlValidator === null) {
            $this->crlValidator = new CRLValidator();
        }
    }
    
    /**
     * 检查证书是否已被撤销
     * 
     * @param X509Certificate $certificate 要检查的证书
     * @param X509Certificate $issuer 颁发者证书
     * @return bool 如果证书未被撤销，返回true；如果已撤销或无法确认状态，返回false
     */
    public function check(X509Certificate $certificate, X509Certificate $issuer): bool
    {
        $this->lastCheckStatus = [
            'policy' => $this->policy->value,
            'certificate' => $certificate->getSubject(),
            'issuer' => $issuer->getSubject(),
            'result' => false,
            'methods_tried' => [],
        ];
        
        // 如果撤销检查被禁用，直接返回true
        if ($this->policy === RevocationPolicy::DISABLED) {
            $this->lastCheckStatus['result'] = true;
            return true;
        }
        
        // 根据策略执行撤销检查
        switch ($this->policy) {
            case RevocationPolicy::OCSP_ONLY:
                return $this->checkOCSP($certificate, $issuer);
                
            case RevocationPolicy::CRL_ONLY:
                return $this->checkCRL($certificate, $issuer);
                
            case RevocationPolicy::OCSP_PREFERRED:
                $ocspResult = $this->checkOCSP($certificate, $issuer);
                if ($ocspResult || $this->lastCheckStatus['ocsp_conclusive'] ?? false) {
                    return $ocspResult;
                }
                return $this->checkCRL($certificate, $issuer);
                
            case RevocationPolicy::CRL_PREFERRED:
                $crlResult = $this->checkCRL($certificate, $issuer);
                if ($crlResult || $this->lastCheckStatus['crl_conclusive'] ?? false) {
                    return $crlResult;
                }
                return $this->checkOCSP($certificate, $issuer);
                
            case RevocationPolicy::SOFT_FAIL:
                // 尝试所有方法，但网络错误时不失败
                try {
                    $ocspResult = $this->checkOCSP($certificate, $issuer);
                    if ($ocspResult || $this->lastCheckStatus['ocsp_conclusive'] ?? false) {
                        return $ocspResult;
                    }
                } catch (\Exception $e) {
                    $this->lastCheckStatus['ocsp_error'] = $e->getMessage();
                }
                
                try {
                    $crlResult = $this->checkCRL($certificate, $issuer);
                    return $crlResult;
                } catch (\Exception $e) {
                    $this->lastCheckStatus['crl_error'] = $e->getMessage();
                }
                
                // 在软失败模式下，若所有方法失败，仍然返回true
                $this->lastCheckStatus['result'] = true;
                return true;
                
            case RevocationPolicy::HARD_FAIL:
            default:
                // 尝试所有方法，任何错误都视为失败
                try {
                    $ocspResult = $this->checkOCSP($certificate, $issuer);
                    if ($ocspResult || $this->lastCheckStatus['ocsp_conclusive'] ?? false) {
                        return $ocspResult;
                    }
                } catch (\Exception $e) {
                    $this->lastCheckStatus['ocsp_error'] = $e->getMessage();
                }
                
                try {
                    return $this->checkCRL($certificate, $issuer);
                } catch (\Exception $e) {
                    $this->lastCheckStatus['crl_error'] = $e->getMessage();
                    // 在硬失败模式下，所有方法失败时返回false
                    return false;
                }
        }
    }
    
    /**
     * 获取上次检查的结果详情
     * 
     * @return array 包含状态详情的数组
     */
    public function getLastCheckStatus(): array
    {
        return $this->lastCheckStatus;
    }
    
    /**
     * 设置撤销检查策略
     * 
     * @param RevocationPolicy $policy 新策略
     * @return self 当前实例，用于链式调用
     */
    public function setPolicy(RevocationPolicy $policy): self
    {
        $this->policy = $policy;
        return $this;
    }
    
    /**
     * 获取当前撤销检查策略
     * 
     * @return RevocationPolicy 当前策略
     */
    public function getPolicy(): RevocationPolicy
    {
        return $this->policy;
    }
    
    /**
     * 使用OCSP检查证书撤销状态
     * 
     * @param X509Certificate $certificate 要检查的证书
     * @param X509Certificate $issuer 颁发者证书
     * @return bool 如果证书未被撤销，返回true
     * @throws RevocationCheckException 当OCSP检查发生错误时
     */
    private function checkOCSP(X509Certificate $certificate, X509Certificate $issuer): bool
    {
        if ($this->ocspClient === null) {
            throw new RevocationCheckException('OCSP客户端未初始化，无法进行OCSP检查');
        }
        
        $this->lastCheckStatus['methods_tried'][] = 'ocsp';
        
        try {
            $response = $this->ocspClient->checkCertificate($certificate, $issuer);
            $certStatus = $response->getCertStatus();
            
            // 将整数状态代码转换为字符串以存储在状态数组中
            $statusMap = [
                0 => 'good',
                1 => 'revoked',
                2 => 'unknown'
            ];
            $status = $statusMap[$certStatus] ?? 'unknown';
            
            $this->lastCheckStatus['ocsp_status'] = $status;
            $this->lastCheckStatus['ocsp_conclusive'] = true;
            
            // 如果状态为"good"(0)，表示证书未被撤销
            $result = $certStatus === 0;
            $this->lastCheckStatus['result'] = $result;
            return $result;
        } catch (\Exception $e) {
            $this->lastCheckStatus['ocsp_error'] = $e->getMessage();
            $this->lastCheckStatus['ocsp_conclusive'] = false;
            
            if ($this->policy === RevocationPolicy::HARD_FAIL || 
                $this->policy === RevocationPolicy::OCSP_ONLY) {
                throw new RevocationCheckException('OCSP检查失败：' . $e->getMessage(), 0, $e);
            }
            
            return false;
        }
    }
    
    /**
     * 使用CRL检查证书撤销状态
     * 
     * @param X509Certificate $certificate 要检查的证书
     * @param X509Certificate $issuer 颁发者证书
     * @return bool 如果证书未被撤销，返回true
     * @throws RevocationCheckException 当CRL检查发生错误时
     */
    private function checkCRL(X509Certificate $certificate, X509Certificate $issuer): bool
    {
        if ($this->crlValidator === null) {
            throw new RevocationCheckException('CRL验证器未初始化，无法进行CRL检查');
        }
        
        $this->lastCheckStatus['methods_tried'][] = 'crl';
        
        try {
            // 从颁发者证书获取CRL分发点
            $crlDPs = $issuer->getExtension('cRLDistributionPoints');
            if (empty($crlDPs)) {
                $this->lastCheckStatus['crl_error'] = '颁发者证书中未找到CRL分发点';
                $this->lastCheckStatus['crl_conclusive'] = false;
                
                if ($this->policy === RevocationPolicy::HARD_FAIL || 
                    $this->policy === RevocationPolicy::CRL_ONLY) {
                    throw new RevocationCheckException('颁发者证书中未找到CRL分发点');
                }
                
                return false;
            }
            
            // 检查证书是否在CRL中
            $isRevoked = $this->crlValidator->isRevoked($certificate, $issuer);
            
            $this->lastCheckStatus['crl_status'] = $isRevoked ? 'revoked' : 'good';
            $this->lastCheckStatus['crl_conclusive'] = true;
            
            $result = !$isRevoked;
            $this->lastCheckStatus['result'] = $result;
            return $result;
        } catch (\Exception $e) {
            $this->lastCheckStatus['crl_error'] = $e->getMessage();
            $this->lastCheckStatus['crl_conclusive'] = false;
            
            if ($this->policy === RevocationPolicy::HARD_FAIL || 
                $this->policy === RevocationPolicy::CRL_ONLY) {
                throw new RevocationCheckException('CRL检查失败：' . $e->getMessage(), 0, $e);
            }
            
            return false;
        }
    }
    
    /**
     * 检查当前策略是否需要OCSP
     * 
     * @return bool 如果需要OCSP，返回true
     */
    private function requiresOCSP(): bool
    {
        return $this->policy !== RevocationPolicy::DISABLED && 
               $this->policy !== RevocationPolicy::CRL_ONLY;
    }
    
    /**
     * 检查当前策略是否需要CRL
     * 
     * @return bool 如果需要CRL，返回true
     */
    private function requiresCRL(): bool
    {
        return $this->policy !== RevocationPolicy::DISABLED && 
               $this->policy !== RevocationPolicy::OCSP_ONLY;
    }
} 