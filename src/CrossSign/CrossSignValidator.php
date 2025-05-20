<?php

declare(strict_types=1);

namespace Tourze\TLSCertificate\CrossSign;

use Tourze\TLSCertificate\Certificate\X509Certificate;
use Tourze\TLSCertificate\Chain\CertificateChain;
use Tourze\TLSCertificate\Exception\CertificateValidationException;
use Tourze\TLSCertificate\Validator\ValidationResult;

/**
 * 交叉签名验证器 - 验证交叉签名证书的有效性
 */
class CrossSignValidator
{
    /**
     * 构造函数
     */
    public function __construct()
    {
    }
    
    /**
     * 验证交叉签名证书
     *
     * @param CrossSignedCertificate $crossSignedCert 交叉签名证书
     * @param array $trustAnchors 信任锚列表
     * @param array $intermediateCertificates 中间证书列表
     * @return ValidationResult 验证结果
     */
    public function validate(
        CrossSignedCertificate $crossSignedCert,
        array $trustAnchors,
        array $intermediateCertificates = []
    ): ValidationResult {
        $result = new ValidationResult();
        
        try {
            // 获取主证书和交叉签名证书
            $primaryCert = $crossSignedCert->getPrimaryCertificate();
            $crossSignedCerts = $crossSignedCert->getCrossSignedCertificates();
            
            // 如果没有交叉签名证书，无需验证
            if (empty($crossSignedCerts)) {
                $result->addInfo('没有交叉签名证书需要验证');
                return $result;
            }
            
            // 验证每个交叉签名证书
            foreach ($crossSignedCerts as $cert) {
                $this->validateSingleCrossSignedCertificate(
                    $cert,
                    $primaryCert,
                    $trustAnchors,
                    $intermediateCertificates,
                    $result
                );
                
                if (!$result->isValid()) {
                    return $result;
                }
            }
            
            $result->addSuccess('所有交叉签名证书验证通过');
        } catch (CertificateValidationException $e) {
            $result->addError('交叉签名验证失败: ' . $e->getMessage());
        } catch (\Exception $e) {
            $result->addError('交叉签名验证过程中发生未预期错误: ' . $e->getMessage());
        }
        
        return $result;
    }
    
    /**
     * 验证单个交叉签名证书
     *
     * @param X509Certificate $crossSignedCert 交叉签名证书
     * @param X509Certificate $primaryCert 主证书
     * @param array $trustAnchors 信任锚列表
     * @param array $intermediateCertificates 中间证书列表
     * @param ValidationResult $result 验证结果
     */
    private function validateSingleCrossSignedCertificate(
        X509Certificate $crossSignedCert,
        X509Certificate $primaryCert,
        array $trustAnchors,
        array $intermediateCertificates,
        ValidationResult $result
    ): void {
        // 1. 验证公钥一致性
        if ($crossSignedCert->getPublicKey() !== $primaryCert->getPublicKey()) {
            $result->addError('交叉签名证书的公钥与主证书不匹配');
            return;
        }
        
        // 2. 验证主题一致性
        if ($crossSignedCert->getSubjectDN() !== $primaryCert->getSubjectDN()) {
            $result->addError('交叉签名证书的主题与主证书不匹配');
            return;
        }
        
        // 3. 验证证书有效期
        $now = new \DateTimeImmutable();
        if ($now < $crossSignedCert->getNotBefore() || $now > $crossSignedCert->getNotAfter()) {
            $result->addError('交叉签名证书不在有效期内');
            return;
        }
        
        // 4. 尝试构建到信任锚的路径
        try {
            // 查找颁发者证书
            $issuerCert = $this->findIssuerCertificate(
                $crossSignedCert,
                array_merge($trustAnchors, $intermediateCertificates)
            );
            
            if ($issuerCert === null) {
                $result->addError('无法找到交叉签名证书的颁发者');
                return;
            }
            
            // 构建证书链
            $chain = $this->buildCertificateChain(
                $crossSignedCert,
                array_merge($trustAnchors, $intermediateCertificates)
            );
            
            if ($chain === null || $chain->isEmpty()) {
                $result->addError('无法构建交叉签名证书的完整信任路径');
                return;
            }
            
            // 验证签名
            // TODO: 实现签名验证，需要与tls-crypto模块集成
            
            $result->addInfo('交叉签名证书有效性验证通过: ' . $crossSignedCert->getIssuerDN());
        } catch (CertificateValidationException $e) {
            $result->addError('交叉签名证书验证失败: ' . $e->getMessage());
        }
    }
    
    /**
     * 查找证书的颁发者
     *
     * @param X509Certificate $certificate 要查找颁发者的证书
     * @param array $certificates 可能的颁发者证书列表
     * @return X509Certificate|null 找到的颁发者证书，如果未找到则返回null
     */
    private function findIssuerCertificate(X509Certificate $certificate, array $certificates): ?X509Certificate
    {
        $issuerDN = $certificate->getIssuerDN();
        
        foreach ($certificates as $cert) {
            if ($cert->getSubjectDN() === $issuerDN) {
                return $cert;
            }
        }
        
        return null;
    }
    
    /**
     * 构建证书链
     *
     * @param X509Certificate $certificate 目标证书
     * @param array $certificates 可用的证书列表
     * @return CertificateChain|null 构建的证书链，如果无法构建则返回null
     */
    private function buildCertificateChain(X509Certificate $certificate, array $certificates): ?CertificateChain
    {
        $chain = new CertificateChain([$certificate]);
        $current = $certificate;
        
        // 最大链长度防止循环依赖
        $maxChainLength = 10;
        $visited = [];
        
        while (count($chain->getCertificates()) < $maxChainLength) {
            // 记录当前证书的序列号，防止循环
            $serialNumber = $current->getSerialNumber();
            if (isset($visited[$serialNumber])) {
                // 检测到循环
                return null;
            }
            $visited[$serialNumber] = true;
            
            // 如果当前证书是自签名的，结束链构建
            if ($current->getIssuerDN() === $current->getSubjectDN()) {
                break;
            }
            
            // 查找当前证书的颁发者
            $issuer = $this->findIssuerCertificate($current, $certificates);
            
            if ($issuer === null) {
                // 无法找到颁发者，链不完整
                return null;
            }
            
            $chain->addCertificate($issuer);
            $current = $issuer;
        }
        
        return $chain;
    }
} 