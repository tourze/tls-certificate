<?php

declare(strict_types=1);

namespace Tourze\TLSCertificate\Revocation\CRL;

use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;
use Tourze\TLSCertificate\Certificate\X509Certificate;
use Tourze\TLSCertificate\Exception\CRLException;

/**
 * CRL更新器 - 负责CRL的自动更新和刷新
 */
class CRLUpdater
{
    /**
     * @var CRLParser
     */
    private CRLParser $crlParser;
    
    /**
     * @var CRLCache
     */
    private CRLCache $crlCache;
    
    /**
     * @var LoggerInterface
     */
    private LoggerInterface $logger;
    
    /**
     * @var int 更新前的默认过期阈值（秒）
     */
    private int $refreshThreshold = 3600; // 默认1小时
    
    /**
     * 构造函数
     *
     * @param CRLParser $crlParser CRL解析器
     * @param CRLCache $crlCache CRL缓存
     * @param LoggerInterface|null $logger 日志记录器
     */
    public function __construct(
        CRLParser $crlParser, 
        CRLCache $crlCache, 
        ?LoggerInterface $logger = null
    ) {
        $this->crlParser = $crlParser;
        $this->crlCache = $crlCache;
        $this->logger = $logger ?? new NullLogger();
    }
    
    /**
     * 设置刷新阈值
     *
     * @param int $seconds 过期前多少秒开始刷新
     * @return self
     */
    public function setRefreshThreshold(int $seconds): self
    {
        $this->refreshThreshold = $seconds;
        return $this;
    }
    
    /**
     * 从证书获取并更新CRL
     *
     * @param X509Certificate $certificate 证书
     * @param bool $silentFailure 是否静默失败
     * @return CertificateRevocationList|null 获取到的CRL或null（如果失败）
     */
    public function updateFromCertificate(X509Certificate $certificate, bool $silentFailure = false): ?CertificateRevocationList
    {
        try {
            $issuerDN = $certificate->getIssuerDN();
            
            // 获取证书中的CRL分发点
            $distributionPoints = $this->crlParser->extractCRLDistributionPoints($certificate);
            if (empty($distributionPoints)) {
                $this->logger->warning("证书没有CRL分发点: {$certificate->getSubjectDN()}");
                return null;
            }
            
            // 尝试每个分发点
            foreach ($distributionPoints as $url) {
                try {
                    // 尝试更新
                    $success = $this->updateCRL($issuerDN, $url, true);
                    if ($success) {
                        return $this->crlCache->get($issuerDN);
                    }
                } catch (\Exception $e) {
                    $this->logger->warning("从分发点 {$url} 更新CRL失败: " . $e->getMessage());
                    // 继续尝试下一个分发点
                }
            }
            
            // 所有分发点都失败，但可能缓存中已有CRL
            $cachedCRL = $this->crlCache->get($issuerDN);
            if ($cachedCRL !== null) {
                $this->logger->info("所有CRL分发点均失败，使用缓存的CRL: {$issuerDN}");
                return $cachedCRL;
            }
            
            throw new CRLException("无法从任何分发点获取CRL: " . implode(', ', $distributionPoints));
        } catch (\Exception $e) {
            if ($silentFailure) {
                $this->logger->error("更新CRL失败: " . $e->getMessage());
                return null;
            }
            
            throw $e;
        }
    }
    
    /**
     * 更新特定颁发者的CRL
     *
     * @param string $issuerDN 颁发者DN
     * @param string $url CRL分发点URL
     * @param bool $silentFailure 是否静默失败
     * @return bool 是否成功更新
     */
    public function updateCRL(string $issuerDN, string $url, bool $silentFailure = false): bool
    {
        try {
            // 检查是否已有此颁发者的CRL
            $currentCRL = $this->crlCache->get($issuerDN);
            
            // 如果有当前CRL且不需要更新，则跳过
            if ($currentCRL !== null && !$this->crlCache->isExpiringSoon($issuerDN, $this->refreshThreshold)) {
                $this->logger->debug("CRL无需更新: {$issuerDN}");
                return true;
            }
            
            // 获取新的CRL
            $this->logger->info("正在从 {$url} 获取CRL");
            $newCRL = $this->crlParser->fetchFromURL($url);
            
            // 验证新CRL是否属于同一颁发者
            if ($newCRL->getIssuerDN() !== $issuerDN) {
                $this->logger->warning("获取到的CRL颁发者不匹配: 预期 {$issuerDN}, 实际 {$newCRL->getIssuerDN()}");
                return false;
            }
            
            // 如果有当前CRL，检查新CRL是否更新
            if ($currentCRL !== null) {
                // 检查CRL编号
                $currentCRLNumber = (int)$currentCRL->getCRLNumber();
                $newCRLNumber = (int)$newCRL->getCRLNumber();
                
                if ($newCRLNumber < $currentCRLNumber) {
                    $this->logger->warning("拒绝更新CRL：新CRL编号 ({$newCRLNumber}) 低于当前编号 ({$currentCRLNumber})");
                    return false;
                }
                
                if ($newCRLNumber === $currentCRLNumber && $newCRL->getThisUpdate() <= $currentCRL->getThisUpdate()) {
                    $this->logger->debug("CRL未更新: {$issuerDN}");
                    return true;
                }
            }
            
            // 更新缓存
            $this->crlCache->add($issuerDN, $newCRL);
            $this->logger->info("已更新 {$issuerDN} 的CRL");
            
            return true;
        } catch (\Exception $e) {
            if ($silentFailure) {
                $this->logger->error("更新CRL失败: " . $e->getMessage());
                return false;
            }
            
            throw $e;
        }
    }
    
    /**
     * 清理过期的CRL
     *
     * @return int 清理的CRL数量
     */
    public function cleanupExpiredCRLs(): int
    {
        $count = $this->crlCache->removeExpired();
        $this->logger->info("已清理 {$count} 个过期CRL");
        return $count;
    }
}
