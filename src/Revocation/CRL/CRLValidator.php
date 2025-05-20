<?php

declare(strict_types=1);

namespace Tourze\TLSCertificate\Revocation\CRL;

use DateTimeImmutable;
use Tourze\TLSCertificate\Certificate\X509Certificate;
use Tourze\TLSCertificate\Crypto\SignatureVerifier;
use Tourze\TLSCertificate\Exception\CRLException;
use Tourze\TLSCertificate\Validator\ValidationResult;

/**
 * CRL验证器 - 验证证书撤销列表的有效性
 */
class CRLValidator
{
    /**
     * @var SignatureVerifier|null 签名验证器
     */
    private ?SignatureVerifier $signatureVerifier;
    
    /**
     * 构造函数
     *
     * @param SignatureVerifier|null $signatureVerifier 签名验证器
     */
    public function __construct(?SignatureVerifier $signatureVerifier = null)
    {
        $this->signatureVerifier = $signatureVerifier;
    }
    
    /**
     * 验证CRL的有效性
     *
     * @param CertificateRevocationList $crl 要验证的CRL
     * @param X509Certificate|null $issuerCert 颁发者证书，如果为null则使用CRL中设置的颁发者证书
     * @param ValidationResult|null $result 验证结果，如果为null则创建新的
     * @return ValidationResult 验证结果
     */
    public function validate(
        CertificateRevocationList $crl,
        ?X509Certificate $issuerCert = null,
        ?ValidationResult $result = null
    ): ValidationResult {
        $result = $result ?? new ValidationResult();
        
        try {
            // 1. 验证颁发者
            $actualIssuerCert = $issuerCert ?? $crl->getIssuerCertificate();
            if ($actualIssuerCert === null) {
                $result->addError('未提供CRL颁发者证书');
                return $result;
            }
            
            if ($actualIssuerCert->getSubjectDN() !== $crl->getIssuerDN()) {
                $result->addError('CRL颁发者与证书主题不匹配');
                return $result;
            }
            
            // 2. 验证有效期
            $now = new DateTimeImmutable();
            
            // 检查CRL是否已生效
            if ($crl->getThisUpdate() > $now) {
                $result->addError('CRL尚未生效');
                return $result;
            }
            
            // 检查CRL是否已过期
            if ($crl->isExpired()) {
                $result->addWarning('CRL已过期');
                // 不直接返回，允许继续验证，但会标记警告
            }
            
            // 3. 验证签名（如果有签名验证器）
            if ($this->signatureVerifier !== null && 
                $crl->getSignatureAlgorithm() !== null && 
                $crl->getSignatureValue() !== null && 
                $crl->getRawData() !== null) {
                
                $issuerPublicKey = $actualIssuerCert->getPublicKey();
                
                // 使用签名验证器验证CRL签名
                $isSignatureValid = $this->signatureVerifier->verify(
                    $crl->getRawData(),
                    $crl->getSignatureValue(),
                    $issuerPublicKey,
                    $crl->getSignatureAlgorithm()
                );
                
                if (!$isSignatureValid) {
                    $result->addError('CRL签名无效');
                    return $result;
                }
                
                $result->addInfo('CRL签名验证通过');
            } else {
                $result->addWarning('跳过CRL签名验证');
            }
            
            $result->addSuccess('CRL验证通过');
            return $result;
            
        } catch (CRLException $e) {
            $result->addError('CRL验证失败: ' . $e->getMessage());
            return $result;
        } catch (\Exception $e) {
            $result->addError('CRL验证过程中发生未预期错误: ' . $e->getMessage());
            return $result;
        }
    }
    
    /**
     * 检查证书是否被撤销
     *
     * @param X509Certificate $certificate 要检查的证书
     * @param CertificateRevocationList $crl 用于检查的CRL
     * @param ValidationResult|null $result 验证结果，如果为null则创建新的
     * @return ValidationResult 验证结果
     */
    public function checkRevocation(
        X509Certificate $certificate,
        CertificateRevocationList $crl,
        ?ValidationResult $result = null
    ): ValidationResult {
        $result = $result ?? new ValidationResult();
        
        try {
            // 首先验证CRL的有效性
            $this->validate($crl, null, $result);
            if (!$result->isValid()) {
                return $result;
            }
            
            // 获取证书序列号
            $serialNumber = $certificate->getSerialNumber();
            
            // 检查证书是否在CRL中
            if ($crl->isRevoked($serialNumber)) {
                $revokedCert = $crl->getRevokedCertificate($serialNumber);
                
                // 检查是否为REMOVE_FROM_CRL标志
                if ($revokedCert->getReason() === 8) { // 8 = REMOVE_FROM_CRL
                    $result->addInfo('证书已从CRL中移除');
                    $result->addSuccess('证书撤销检查通过');
                    return $result;
                }
                
                $revocationDate = $revokedCert->getRevocationDate()->format('Y-m-d H:i:s');
                $reason = $revokedCert->getReasonText();
                
                $result->addError('证书已被撤销，撤销时间: ' . $revocationDate . ', 原因: ' . $reason);
            } else {
                $result->addInfo('证书未被撤销');
                $result->addSuccess('证书撤销检查通过');
            }
            
            return $result;
            
        } catch (CRLException $e) {
            $result->addError('证书撤销检查失败: ' . $e->getMessage());
            return $result;
        } catch (\Exception $e) {
            $result->addError('证书撤销检查过程中发生未预期错误: ' . $e->getMessage());
            return $result;
        }
    }
    
    /**
     * 检查证书颁发者是否匹配CRL颁发者
     *
     * @param X509Certificate $certificate 要检查的证书
     * @param CertificateRevocationList $crl 要检查的CRL
     * @return bool 如果颁发者匹配则返回true
     */
    private function isCRLValidForCertificate(X509Certificate $certificate, CertificateRevocationList $crl): bool
    {
        // 获取证书的颁发者可分辨名称
        $certIssuerDN = $certificate->getIssuerDN();
        
        // 获取CRL的颁发者可分辨名称
        $crlIssuerDN = $crl->getIssuerDN();
        
        // 比较颁发者
        return $certIssuerDN === $crlIssuerDN;
    }
} 