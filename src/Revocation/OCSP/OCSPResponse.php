<?php

declare(strict_types=1);

namespace Tourze\TLSCertificate\Revocation\OCSP;

use DateTimeImmutable;
use Tourze\TLSCertificate\Exception\OCSPException;

/**
 * OCSP响应类 - 解析和处理OCSP响应
 */
class OCSPResponse
{
    /**
     * OCSP响应状态常量
     */
    public const SUCCESSFUL = 0;
    public const MALFORMED_REQUEST = 1;
    public const INTERNAL_ERROR = 2;
    public const TRY_LATER = 3;
    public const SIG_REQUIRED = 5;
    public const UNAUTHORIZED = 6;
    
    /**
     * 证书状态常量
     */
    public const CERT_STATUS_GOOD = 0;
    public const CERT_STATUS_REVOKED = 1;
    public const CERT_STATUS_UNKNOWN = 2;
    
    /**
     * @var int OCSP响应状态
     */
    private int $responseStatus;
    
    /**
     * @var string|null 响应类型
     */
    private ?string $responseType = null;
    
    /**
     * @var int|null 证书状态
     */
    private ?int $certStatus = null;
    
    /**
     * @var DateTimeImmutable|null 撤销时间
     */
    private ?DateTimeImmutable $revocationTime = null;
    
    /**
     * @var int|null 撤销原因
     */
    private ?int $revocationReason = null;
    
    /**
     * @var DateTimeImmutable|null 响应产生时间
     */
    private ?DateTimeImmutable $producedAt = null;
    
    /**
     * @var DateTimeImmutable|null 本次更新时间
     */
    private ?DateTimeImmutable $thisUpdate = null;
    
    /**
     * @var DateTimeImmutable|null 下次更新时间
     */
    private ?DateTimeImmutable $nextUpdate = null;
    
    /**
     * @var string|null 证书序列号
     */
    private ?string $serialNumber = null;
    
    /**
     * @var string|null 响应中的随机数
     */
    private ?string $nonce = null;
    
    /**
     * @var string|null 原始响应数据
     */
    private ?string $rawData = null;
    
    /**
     * 构造函数
     *
     * @param int $responseStatus OCSP响应状态
     * @param string|null $rawData 原始响应数据
     */
    public function __construct(int $responseStatus, ?string $rawData = null)
    {
        $this->responseStatus = $responseStatus;
        $this->rawData = $rawData;
    }
    
    /**
     * 从DER编码数据解析OCSP响应
     *
     * @param string $derData DER编码的OCSP响应数据
     * @return self
     * @throws OCSPException 如果解析失败
     */
    public static function fromDER(string $derData): self
    {
        try {
            // 注意：这里简化了实现，实际应该使用ASN.1库解析OCSP响应
            // RFC 6960 定义了OCSP响应的ASN.1结构
            
            // 占位符实现
            $responseStatus = self::SUCCESSFUL;
            $response = new self($responseStatus, $derData);
            
            // TODO: 实现完整的ASN.1解析
            // 解析基本响应字段
            $response->responseType = 'id-pkix-ocsp-basic';
            $response->certStatus = self::CERT_STATUS_GOOD;
            $response->producedAt = new DateTimeImmutable();
            $response->thisUpdate = new DateTimeImmutable();
            $response->nextUpdate = new DateTimeImmutable('+1 day');
            
            return $response;
        } catch (\Exception $e) {
            throw new OCSPException('解析OCSP响应失败: ' . $e->getMessage(), 0, $e);
        }
    }
    
    /**
     * 从HTTP响应解析OCSP响应
     *
     * @param string $httpResponse HTTP响应内容
     * @return self
     * @throws OCSPException 如果解析失败
     */
    public static function fromHTTP(string $httpResponse): self
    {
        try {
            // 从HTTP响应中提取OCSP响应数据
            // 检查内容类型
            if (strpos($httpResponse, 'Content-Type: application/ocsp-response') === false) {
                throw new OCSPException('HTTP响应内容类型不是application/ocsp-response');
            }
            
            // 提取响应体
            $parts = explode("\r\n\r\n", $httpResponse, 2);
            if (count($parts) !== 2) {
                throw new OCSPException('无效的HTTP响应格式');
            }
            
            $body = $parts[1];
            return self::fromDER($body);
        } catch (\Exception $e) {
            throw new OCSPException('从HTTP响应解析OCSP响应失败: ' . $e->getMessage(), 0, $e);
        }
    }
    
    /**
     * 检查响应是否成功
     *
     * @return bool
     */
    public function isSuccessful(): bool
    {
        return $this->responseStatus === self::SUCCESSFUL;
    }
    
    /**
     * 获取响应状态
     *
     * @return int
     */
    public function getResponseStatus(): int
    {
        return $this->responseStatus;
    }
    
    /**
     * 获取响应状态描述
     *
     * @return string
     */
    public function getResponseStatusText(): string
    {
        $statusMap = [
            self::SUCCESSFUL => '成功',
            self::MALFORMED_REQUEST => '格式错误的请求',
            self::INTERNAL_ERROR => '内部错误',
            self::TRY_LATER => '稍后重试',
            self::SIG_REQUIRED => '需要签名',
            self::UNAUTHORIZED => '未授权'
        ];
        
        return $statusMap[$this->responseStatus] ?? '未知状态(' . $this->responseStatus . ')';
    }
    
    /**
     * 获取证书状态
     *
     * @return int|null
     */
    public function getCertStatus(): ?int
    {
        return $this->certStatus;
    }
    
    /**
     * 获取证书状态描述
     *
     * @return string
     */
    public function getCertStatusText(): string
    {
        if ($this->certStatus === null) {
            return '未知';
        }
        
        $statusMap = [
            self::CERT_STATUS_GOOD => '有效',
            self::CERT_STATUS_REVOKED => '已撤销',
            self::CERT_STATUS_UNKNOWN => '未知'
        ];
        
        return $statusMap[$this->certStatus] ?? '未知状态(' . $this->certStatus . ')';
    }
    
    /**
     * 检查证书是否有效
     *
     * @return bool
     */
    public function isCertificateGood(): bool
    {
        return $this->isSuccessful() && $this->certStatus === self::CERT_STATUS_GOOD;
    }
    
    /**
     * 检查证书是否已撤销
     *
     * @return bool
     */
    public function isCertificateRevoked(): bool
    {
        return $this->isSuccessful() && $this->certStatus === self::CERT_STATUS_REVOKED;
    }
    
    /**
     * 获取撤销时间
     *
     * @return DateTimeImmutable|null
     */
    public function getRevocationTime(): ?DateTimeImmutable
    {
        return $this->revocationTime;
    }
    
    /**
     * 获取撤销原因
     *
     * @return int|null
     */
    public function getRevocationReason(): ?int
    {
        return $this->revocationReason;
    }
    
    /**
     * 获取响应产生时间
     *
     * @return DateTimeImmutable|null
     */
    public function getProducedAt(): ?DateTimeImmutable
    {
        return $this->producedAt;
    }
    
    /**
     * 获取本次更新时间
     *
     * @return DateTimeImmutable|null
     */
    public function getThisUpdate(): ?DateTimeImmutable
    {
        return $this->thisUpdate;
    }
    
    /**
     * 获取下次更新时间
     *
     * @return DateTimeImmutable|null
     */
    public function getNextUpdate(): ?DateTimeImmutable
    {
        return $this->nextUpdate;
    }
    
    /**
     * 检查响应是否已过期
     *
     * @return bool
     */
    public function isExpired(): bool
    {
        if ($this->nextUpdate === null) {
            // 如果没有指定nextUpdate，保守认为已过期
            return true;
        }
        
        return new DateTimeImmutable() > $this->nextUpdate;
    }
    
    /**
     * 获取响应中的随机数
     *
     * @return string|null
     */
    public function getNonce(): ?string
    {
        return $this->nonce;
    }
    
    /**
     * 检查随机数是否匹配
     *
     * @param string $requestNonce 请求中的随机数
     * @return bool
     */
    public function verifyNonce(string $requestNonce): bool
    {
        return $this->nonce !== null && $this->nonce === $requestNonce;
    }
} 