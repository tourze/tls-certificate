<?php

declare(strict_types=1);

namespace Tourze\TLSCertificate\Revocation\CRL;

use DateInterval;
use DateTimeImmutable;

/**
 * CRL缓存 - 缓存已获取的证书撤销列表
 */
class CRLCache
{
    /**
     * @var array<string, CertificateRevocationList> 缓存的CRL，以颁发者DN为键
     */
    private array $cache = [];
    
    /**
     * @var int 快过期阈值（秒）
     */
    private int $expiringThreshold = 3600; // 1小时
    
    /**
     * @var array<string, DateTimeImmutable> 按颁发者DN索引的缓存时间
     */
    private array $cacheTime = [];
    
    /**
     * @var DateInterval 缓存过期时间
     */
    private DateInterval $cacheExpiration;
    
    /**
     * @var int 最大缓存大小
     */
    private int $maxCacheSize;
    
    /**
     * 构造函数
     *
     * @param int $expiringThreshold 快过期阈值（秒）
     * @param string $cacheExpirationTime 缓存过期时间（ISO 8601持续时间格式）
     * @param int $maxCacheSize 最大缓存大小
     */
    public function __construct(int $expiringThreshold = 3600, string $cacheExpirationTime = 'PT1H', int $maxCacheSize = 100)
    {
        $this->expiringThreshold = $expiringThreshold;
        $this->cacheExpiration = new DateInterval($cacheExpirationTime);
        $this->maxCacheSize = $maxCacheSize;
    }
    
    /**
     * 添加CRL到缓存
     *
     * @param string $issuerDN 颁发者可分辨名称
     * @param CertificateRevocationList $crl 要缓存的CRL
     * @return $this
     */
    public function add(string $issuerDN, CertificateRevocationList $crl): self
    {
        $this->cache[$issuerDN] = $crl;
        return $this;
    }
    
    /**
     * 从缓存获取CRL
     *
     * @param string $issuerDN 颁发者可分辨名称
     * @return CertificateRevocationList|null 如果缓存中有CRL则返回，否则返回null
     */
    public function get(string $issuerDN): ?CertificateRevocationList
    {
        return $this->cache[$issuerDN] ?? null;
    }
    
    /**
     * 检查CRL是否即将过期
     *
     * @param string $issuerDN 颁发者可分辨名称
     * @param int|null $threshold 自定义阈值（秒），如果为null则使用默认阈值
     * @return bool 如果CRL即将过期或不存在则返回true
     */
    public function isExpiringSoon(string $issuerDN, ?int $threshold = null): bool
    {
        $crl = $this->get($issuerDN);
        if ($crl === null) {
            return true;
        }
        
        $nextUpdate = $crl->getNextUpdate();
        if ($nextUpdate === null) {
            return true;
        }
        
        $now = new DateTimeImmutable();
        $thresholdSeconds = $threshold ?? $this->expiringThreshold;
        $expiringTime = new DateTimeImmutable('+' . $thresholdSeconds . ' seconds');
        
        return $nextUpdate <= $expiringTime;
    }
    
    /**
     * 移除过期的CRL
     *
     * @return int 已移除的CRL数量
     */
    public function removeExpired(): int
    {
        $now = new DateTimeImmutable();
        $removedCount = 0;
        
        foreach ($this->cache as $issuerDN => $crl) {
            $nextUpdate = $crl->getNextUpdate();
            if ($nextUpdate === null || $nextUpdate <= $now) {
                unset($this->cache[$issuerDN]);
                $removedCount++;
            }
        }
        
        return $removedCount;
    }
    
    /**
     * 清除缓存
     *
     * @return $this
     */
    public function clear(): self
    {
        $this->cache = [];
        $this->cacheTime = [];
        return $this;
    }
    
    /**
     * 获取缓存中的CRL数量
     *
     * @return int
     */
    public function count(): int
    {
        return count($this->cache);
    }
    
    /**
     * 获取所有缓存的CRL的颁发者DN
     *
     * @return array<string>
     */
    public function getIssuers(): array
    {
        return array_keys($this->cache);
    }
    
    /**
     * 设置快过期阈值
     *
     * @param int $threshold 快过期阈值（秒）
     * @return $this
     */
    public function setExpiringThreshold(int $threshold): self
    {
        $this->expiringThreshold = $threshold;
        return $this;
    }
    
    /**
     * 获取缓存大小
     *
     * @return int 当前缓存的CRL数量
     */
    public function getSize(): int
    {
        return count($this->cache);
    }
    
    /**
     * 设置缓存过期时间
     *
     * @param string $cacheExpirationTime 缓存过期时间（ISO 8601持续时间格式）
     * @return $this
     */
    public function setCacheExpiration(string $cacheExpirationTime): self
    {
        $this->cacheExpiration = new DateInterval($cacheExpirationTime);
        return $this;
    }
    
    /**
     * 设置最大缓存大小
     *
     * @param int $maxCacheSize 最大缓存大小
     * @return $this
     */
    public function setMaxCacheSize(int $maxCacheSize): self
    {
        $this->maxCacheSize = $maxCacheSize;
        
        // 如果当前缓存大小超过新的最大缓存大小，删除最旧的条目
        while (count($this->cache) > $this->maxCacheSize) {
            $oldestTime = null;
            $oldestKey = null;
            
            foreach ($this->cacheTime as $key => $time) {
                if ($oldestTime === null || $time < $oldestTime) {
                    $oldestTime = $time;
                    $oldestKey = $key;
                }
            }
            
            if ($oldestKey !== null) {
                unset($this->cache[$oldestKey]);
                unset($this->cacheTime[$oldestKey]);
            }
        }
        
        return $this;
    }
}
