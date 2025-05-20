<?php

declare(strict_types=1);

namespace Tourze\TLSCertificate\Example;

use Tourze\TLSCertificate\Certificate\X509Certificate;
use Tourze\TLSCertificate\Certificate\X509CertificateLoader;
use Tourze\TLSCertificate\Crypto\SignatureVerifier;
use Tourze\TLSCertificate\Revocation\CRL\CRLCache;
use Tourze\TLSCertificate\Revocation\CRL\CRLParser;
use Tourze\TLSCertificate\Revocation\CRL\CRLUpdater;
use Tourze\TLSCertificate\Revocation\CRL\CRLValidator;
use Tourze\TLSCertificate\Validator\ValidationResult;

/**
 * CRL验证示例
 */
class ValidateCRLExample
{
    /**
     * @var CRLCache CRL缓存
     */
    private CRLCache $crlCache;
    
    /**
     * @var CRLParser CRL解析器
     */
    private CRLParser $crlParser;
    
    /**
     * @var CRLUpdater CRL更新器
     */
    private CRLUpdater $crlUpdater;
    
    /**
     * @var CRLValidator CRL验证器
     */
    private CRLValidator $crlValidator;
    
    /**
     * @var SignatureVerifier|null 签名验证器
     */
    private ?SignatureVerifier $signatureVerifier;
    
    /**
     * 构造函数
     */
    public function __construct(?SignatureVerifier $signatureVerifier = null)
    {
        $this->crlCache = new CRLCache();
        $this->crlParser = new CRLParser();
        $this->crlUpdater = new CRLUpdater($this->crlParser, $this->crlCache);
        $this->signatureVerifier = $signatureVerifier;
        $this->crlValidator = new CRLValidator($signatureVerifier);
    }
    
    /**
     * 验证证书是否被撤销
     *
     * @param X509Certificate $certificate 要验证的证书
     * @param bool $forceUpdate 是否强制更新CRL
     * @return ValidationResult 验证结果
     */
    public function validateCertificateRevocation(
        X509Certificate $certificate,
        bool $forceUpdate = false
    ): ValidationResult {
        $result = new ValidationResult();
        
        try {
            // 获取证书颁发者
            $issuerDN = $certificate->getIssuerDN();
            
            // 检查是否有缓存的CRL
            $crl = $this->crlCache->get($issuerDN);
            
            // 如果没有CRL或强制更新，尝试获取
            if ($crl === null || $forceUpdate || $this->crlCache->isExpiringSoon($issuerDN)) {
                $crl = $this->crlUpdater->updateFromCertificate($certificate, true);
                
                if ($crl === null) {
                    $result->addWarning('无法获取CRL，继续但不进行撤销检查');
                    return $result;
                }
            }
            
            // 检查证书撤销状态
            return $this->crlValidator->checkRevocation($certificate, $crl);
            
        } catch (\Exception $e) {
            $result->addError('证书撤销验证失败: ' . $e->getMessage());
            return $result;
        }
    }
    
    /**
     * 从PEM格式的证书文件验证撤销状态
     *
     * @param string $certPath 证书文件路径
     * @param bool $forceUpdate 是否强制更新CRL
     * @return ValidationResult 验证结果
     */
    public function validateFromPEMFile(string $certPath, bool $forceUpdate = false): ValidationResult
    {
        $result = new ValidationResult();
        
        try {
            if (!file_exists($certPath)) {
                $result->addError('证书文件不存在: ' . $certPath);
                return $result;
            }
            
            $pemData = file_get_contents($certPath);
            if ($pemData === false) {
                $result->addError('无法读取证书文件: ' . $certPath);
                return $result;
            }
            
            $loader = new X509CertificateLoader();
            $certificate = $loader->loadFromPEMString($pemData);
            
            return $this->validateCertificateRevocation($certificate, $forceUpdate);
            
        } catch (\Exception $e) {
            $result->addError('证书文件验证失败: ' . $e->getMessage());
            return $result;
        }
    }
    
    /**
     * 显示验证结果
     *
     * @param ValidationResult $result 验证结果
     * @return string 格式化的结果输出
     */
    public function formatValidationResult(ValidationResult $result): string
    {
        $output = [];
        
        $output[] = "证书撤销状态验证结果:";
        $output[] = "有效性: " . ($result->isValid() ? "有效" : "无效");
        
        if (!empty($result->getErrors())) {
            $output[] = "\n错误:";
            foreach ($result->getErrors() as $error) {
                $output[] = "- " . $error;
            }
        }
        
        if (!empty($result->getWarnings())) {
            $output[] = "\n警告:";
            foreach ($result->getWarnings() as $warning) {
                $output[] = "- " . $warning;
            }
        }
        
        if (!empty($result->getInfoMessages())) {
            $output[] = "\n信息:";
            foreach ($result->getInfoMessages() as $info) {
                $output[] = "- " . $info;
            }
        }
        
        if (!empty($result->getSuccessMessages())) {
            $output[] = "\n成功:";
            foreach ($result->getSuccessMessages() as $success) {
                $output[] = "- " . $success;
            }
        }
        
        return implode("\n", $output);
    }
    
    /**
     * 在控制台输出CRL统计信息
     * 
     * @return string CRL统计信息
     */
    public function printCRLStats(): string
    {
        $output = [];
        $output[] = "CRL缓存统计信息:";
        $output[] = "- 缓存的CRL数量: " . $this->crlCache->count();
        
        $issuers = $this->crlCache->getIssuers();
        if (!empty($issuers)) {
            $output[] = "- 缓存的颁发者:";
            foreach ($issuers as $issuer) {
                $crl = $this->crlCache->get($issuer);
                if ($crl !== null) {
                    $nextUpdate = $crl->getNextUpdate();
                    $nextUpdateStr = $nextUpdate ? $nextUpdate->format('Y-m-d H:i:s') : '未指定';
                    $isExpiring = $this->crlCache->isExpiringSoon($issuer);
                    $status = $isExpiring ? '即将过期' : '有效';
                    
                    $output[] = "  * {$issuer}";
                    $output[] = "    - 下次更新: {$nextUpdateStr}";
                    $output[] = "    - 状态: {$status}";
                    $output[] = "    - CRL序号: {$crl->getCRLNumber()}";
                    $output[] = "    - 撤销证书数量: " . count($crl->getRevokedCertificates());
                }
            }
        }
        
        return implode("\n", $output);
    }
} 