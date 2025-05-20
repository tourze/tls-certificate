<?php

declare(strict_types=1);

namespace Tourze\TLSCertificate\Revocation\OCSP;

use DateTimeImmutable;
use Tourze\TLSCertificate\Certificate\X509Certificate;
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
     * @var string|null 响应者ID
     */
    private ?string $responderID = null;
    
    /**
     * @var string|null 签名算法
     */
    private ?string $signatureAlgorithm = null;
    
    /**
     * @var string|null 签名
     */
    private ?string $signature = null;
    
    /**
     * @var string|null 颁发者名称散列值
     */
    private ?string $issuerNameHash = null;
    
    /**
     * @var string|null 颁发者公钥散列值
     */
    private ?string $issuerKeyHash = null;
    
    /**
     * @var int 响应数据的过期警告秒数
     */
    private int $expiryWarningDays = 172800; // 172800秒 = 2天
    
    /**
     * @var array|null 完整的TBS响应数据
     */
    private ?array $tbsResponseData = null;
    
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
     * @param OCSPResponseParser|null $parser 可选的自定义响应解析器
     * @return self
     * @throws OCSPException 如果解析失败
     */
    public static function fromDER(string $derData, ?OCSPResponseParser $parser = null): self
    {
        try {
            // 创建或使用提供的解析器
            $parser = $parser ?? new OCSPResponseParser($derData);
            
            // 解析响应数据
            $parsedData = $parser->parse();
            
            // 创建响应对象
            $response = new self($parsedData['responseStatus'] ?? self::SUCCESSFUL, $derData);
            
            // 设置解析出的字段
            $response->responseType = $parsedData['responseType'] ?? null;
            $response->certStatus = $parsedData['certStatus'] ?? null;
            $response->producedAt = $parsedData['producedAt'] ?? new DateTimeImmutable();
            $response->thisUpdate = $parsedData['thisUpdate'] ?? new DateTimeImmutable();
            $response->nextUpdate = $parsedData['nextUpdate'] ?? new DateTimeImmutable('+1 day');
            $response->nonce = $parsedData['nonce'] ?? null;
            $response->serialNumber = $parsedData['serialNumber'] ?? null;
            $response->revocationTime = $parsedData['revocationTime'] ?? null;
            $response->revocationReason = $parsedData['revocationReason'] ?? null;
            $response->signature = $parsedData['signature'] ?? null;
            $response->signatureAlgorithm = $parsedData['signatureAlgorithm'] ?? null;
            $response->responderID = $parsedData['responderID'] ?? null;
            $response->issuerNameHash = $parsedData['issuerNameHash'] ?? null;
            $response->issuerKeyHash = $parsedData['issuerKeyHash'] ?? null;
            $response->tbsResponseData = $parsedData;
            
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
        $statusMap = [
            self::CERT_STATUS_GOOD => '有效',
            self::CERT_STATUS_REVOKED => '已撤销',
            self::CERT_STATUS_UNKNOWN => '未知'
        ];
        
        return $statusMap[$this->certStatus ?? -1] ?? '未设置';
    }
    
    /**
     * 检查证书是否有效
     *
     * @return bool
     */
    public function isCertificateGood(): bool
    {
        return $this->certStatus === self::CERT_STATUS_GOOD;
    }
    
    /**
     * 检查证书是否已撤销
     *
     * @return bool
     */
    public function isCertificateRevoked(): bool
    {
        return $this->certStatus === self::CERT_STATUS_REVOKED;
    }
    
    /**
     * 判断证书状态是否为未知
     *
     * @return bool
     */
    public function isCertificateUnknown(): bool
    {
        return $this->certStatus === self::CERT_STATUS_UNKNOWN;
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
     * 获取证书序列号
     *
     * @return string|null
     */
    public function getSerialNumber(): ?string
    {
        return $this->serialNumber;
    }
    
    /**
     * 检查响应是否已过期
     *
     * @return bool
     */
    public function isExpired(): bool
    {
        if ($this->nextUpdate === null) {
            return false; // 如果没有nextUpdate字段，我们假设不会过期
        }
        
        $now = new DateTimeImmutable();
        return $this->nextUpdate < $now;
    }
    
    /**
     * 检查响应是否即将过期
     * 
     * @param int $warningDays 提前警告天数
     * @return bool 如果响应即将过期则返回true
     */
    public function isExpiringSoon(int $warningDays = 0): bool
    {
        // 如果没有设置nextUpdate，无法判断过期时间
        if ($this->nextUpdate === null) {
            return false;
        }
        
        // 使用默认警告天数或者传入的参数
        $days = $warningDays > 0 ? $warningDays : $this->expiryWarningDays;
        
        // 计算警告时间点
        $now = new DateTimeImmutable();
        $warningThreshold = new DateTimeImmutable('+' . $days . ' seconds');
        
        // 如果nextUpdate在当前时间和警告阈值之间，则即将过期
        return $this->nextUpdate > $now && $this->nextUpdate <= $warningThreshold;
    }
    
    /**
     * 获取随机数
     *
     * @return string|null
     */
    public function getNonce(): ?string
    {
        return $this->nonce;
    }
    
    /**
     * 验证响应中的随机数是否与请求一致
     *
     * @param string $requestNonce 请求中的随机数
     * @return bool
     */
    public function verifyNonce(string $requestNonce): bool
    {
        return $this->nonce !== null && $this->nonce === $requestNonce;
    }
    
    /**
     * 设置过期警告秒数
     * 
     * @param int $seconds 秒数
     * @return $this
     */
    public function setExpiryWarningDays(int $seconds): self
    {
        $this->expiryWarningDays = $seconds;
        return $this;
    }
    
    /**
     * 获取响应者ID
     * 
     * @return string|null
     */
    public function getResponderID(): ?string
    {
        return $this->responderID;
    }
    
    /**
     * 获取签名算法
     * 
     * @return string|null
     */
    public function getSignatureAlgorithm(): ?string
    {
        return $this->signatureAlgorithm;
    }
    
    /**
     * 获取签名
     * 
     * @return string|null
     */
    public function getSignature(): ?string
    {
        return $this->signature;
    }
    
    /**
     * 获取颁发者名称散列值
     * 
     * @return string|null
     */
    public function getIssuerNameHash(): ?string
    {
        return $this->issuerNameHash;
    }
    
    /**
     * 获取颁发者公钥散列值
     * 
     * @return string|null
     */
    public function getIssuerKeyHash(): ?string
    {
        return $this->issuerKeyHash;
    }
    
    /**
     * 获取TBS响应数据
     * 
     * @return array|null
     */
    public function getTBSResponseData(): ?array
    {
        return $this->tbsResponseData;
    }
    
    /**
     * 检查此响应是否与请求匹配
     * 
     * @param OCSPRequest $request OCSP请求
     * @return bool 如果匹配则返回true
     */
    public function matchesRequest(OCSPRequest $request): bool
    {
        // 如果颁发者名称散列和公钥散列为空，无法匹配
        if ($this->issuerNameHash === null || $this->issuerKeyHash === null) {
            return false;
        }
        
        // 检查散列值和序列号是否匹配
        $nameHashMatch = $this->issuerNameHash === $request->getIssuerNameHash();
        $keyHashMatch = $this->issuerKeyHash === $request->getIssuerKeyHash();
        $serialMatch = $this->serialNumber === $request->getSerialNumber();
        
        return $nameHashMatch && $keyHashMatch && $serialMatch;
    }
    
    /**
     * 验证OCSP响应的签名
     *
     * @param X509Certificate $certificate 用于验证签名的证书
     * @param \Tourze\TLSCertificate\Crypto\SignatureVerifier|null $verifier 签名验证器
     * @return bool 如果签名有效则返回true
     */
    public function verifySignature(X509Certificate $certificate, $verifier = null): bool
    {
        // 如果没有签名或TBS数据，无法验证
        if ($this->signature === null || $this->tbsResponseData === null || !is_array($this->tbsResponseData)) {
            return false;
        }
        
        try {
            $publicKey = $certificate->getPublicKey();
            if ($publicKey === null) {
                return false;
            }
            
            // 如果没有提供验证器，尝试创建一个
            if ($verifier === null) {
                // 应该使用实际的签名验证器类，这里仅做示例
                throw new OCSPException('必须提供签名验证器');
            }
            
            // 对TBS数据进行散列并验证签名
            $tbsData = is_string($this->tbsResponseData) ? $this->tbsResponseData : json_encode($this->tbsResponseData);
            return $verifier->verify($tbsData, $this->signature, $publicKey, $this->signatureAlgorithm);
        } catch (\Exception $e) {
            // 日志记录异常
            return false;
        }
    }
} 