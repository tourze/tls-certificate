<?php

declare(strict_types=1);

namespace Tourze\TLSCertificate\Revocation\OCSP;

use Tourze\TLSCertificate\Certificate\X509Certificate;
use Tourze\TLSCertificate\Exception\OCSPException;
use Tourze\TLSCertificate\Validator\ValidationResult;

/**
 * OCSP客户端类 - 用于发送OCSP请求和处理响应
 */
class OCSPClient
{
    /**
     * @var int 连接超时时间（秒）
     */
    private int $connectTimeout = 5;
    
    /**
     * @var int 响应超时时间（秒）
     */
    private int $responseTimeout = 10;
    
    /**
     * @var bool 是否使用随机数
     */
    private bool $useNonce = true;
    
    /**
     * @var array<string, OCSPResponse> 响应缓存
     */
    private array $responseCache = [];
    
    /**
     * 构造函数
     *
     * @param int $connectTimeout 连接超时时间（秒）
     * @param int $responseTimeout 响应超时时间（秒）
     * @param bool $useNonce 是否使用随机数
     */
    public function __construct(int $connectTimeout = 5, int $responseTimeout = 10, bool $useNonce = true)
    {
        $this->connectTimeout = $connectTimeout;
        $this->responseTimeout = $responseTimeout;
        $this->useNonce = $useNonce;
    }
    
    /**
     * 检查证书状态
     *
     * @param X509Certificate $certificate 要检查的证书
     * @param X509Certificate $issuerCertificate 颁发者证书
     * @param string $ocspUrl OCSP响应者URL
     * @param ValidationResult|null $result 验证结果，如果为null则创建新的
     * @return ValidationResult 验证结果
     */
    public function check(
        X509Certificate $certificate,
        X509Certificate $issuerCertificate,
        string $ocspUrl,
        ?ValidationResult $result = null
    ): ValidationResult {
        $result = $result ?? new ValidationResult();
        
        try {
            // 1. 创建OCSP请求
            $request = OCSPRequest::fromCertificate(
                $certificate,
                $issuerCertificate,
                'sha1',
                $this->useNonce
            );
            
            // 2. 检查缓存
            $cacheKey = $this->getCacheKey($certificate, $issuerCertificate);
            if (isset($this->responseCache[$cacheKey])) {
                $cachedResponse = $this->responseCache[$cacheKey];
                
                // 检查缓存是否已过期
                if (!$cachedResponse->isExpired()) {
                    $result->addInfo('使用缓存的OCSP响应');
                    return $this->validateResponse($cachedResponse, $request, $result);
                }
                
                $result->addInfo('缓存的OCSP响应已过期，将获取新响应');
                unset($this->responseCache[$cacheKey]);
            }
            
            // 3. 发送请求获取响应
            $encodedRequest = $request->encode();
            $response = $this->sendRequest($ocspUrl, $encodedRequest);
            
            // 4. 解析响应
            $ocspResponse = OCSPResponse::fromDER($response);
            
            // 5. 验证响应
            $this->validateResponse($ocspResponse, $request, $result);
            
            // 6. 缓存响应（如果成功）
            if ($ocspResponse->isSuccessful() && !$ocspResponse->isExpired()) {
                $this->responseCache[$cacheKey] = $ocspResponse;
            }
            
            return $result;
            
        } catch (OCSPException $e) {
            $result->addError('OCSP检查失败: ' . $e->getMessage());
            return $result;
        } catch (\Exception $e) {
            $result->addError('OCSP检查过程中发生未预期错误: ' . $e->getMessage());
            return $result;
        }
    }
    
    /**
     * 发送OCSP请求并获取响应
     *
     * @param string $url OCSP响应者URL
     * @param string $request 编码的OCSP请求
     * @return string 响应数据
     * @throws OCSPException 如果请求失败
     */
    private function sendRequest(string $url, string $request): string
    {
        try {
            // 创建HTTP上下文
            $context = stream_context_create([
                'http' => [
                    'method' => 'POST',
                    'header' => 'Content-Type: application/ocsp-request' . "\r\n" .
                               'Content-Length: ' . strlen($request) . "\r\n" .
                               'Connection: close',
                    'content' => $request,
                    'timeout' => $this->responseTimeout,
                    'ignore_errors' => true
                ]
            ]);
            
            // 发送请求
            $response = @file_get_contents($url, false, $context);
            if ($response === false) {
                throw new OCSPException('无法连接到OCSP响应者: ' . $url);
            }
            
            // 检查HTTP状态码
            $statusLine = $http_response_header[0] ?? '';
            if (!preg_match('/^HTTP\/\d\.\d\s+(\d+)/', $statusLine, $matches)) {
                throw new OCSPException('无效的HTTP响应');
            }
            
            $statusCode = (int)$matches[1];
            if ($statusCode !== 200) {
                throw new OCSPException('OCSP响应者返回错误状态码: ' . $statusCode);
            }
            
            return $response;
        } catch (OCSPException $e) {
            throw $e;
        } catch (\Exception $e) {
            throw new OCSPException('发送OCSP请求失败: ' . $e->getMessage(), 0, $e);
        }
    }
    
    /**
     * 验证OCSP响应
     *
     * @param OCSPResponse $response OCSP响应
     * @param OCSPRequest $request OCSP请求
     * @param ValidationResult $result 验证结果
     * @return ValidationResult 验证结果
     */
    private function validateResponse(
        OCSPResponse $response,
        OCSPRequest $request,
        ValidationResult $result
    ): ValidationResult {
        // 1. 检查响应状态
        if (!$response->isSuccessful()) {
            $result->addError('OCSP响应不成功: ' . $response->getResponseStatusText());
            return $result;
        }
        
        // 2. 如果使用了随机数，验证随机数匹配
        if ($this->useNonce && 
            $request->getNonce() !== null && 
            !$response->verifyNonce($request->getNonce())) {
            $result->addWarning('OCSP响应中的随机数与请求不匹配');
        }
        
        // 3. 检查证书状态
        if ($response->isCertificateGood()) {
            $result->addInfo('OCSP响应表明证书有效');
            $result->addSuccess('证书未被撤销');
        } elseif ($response->isCertificateRevoked()) {
            $revocationTime = $response->getRevocationTime();
            $revocationTimeStr = $revocationTime ? $revocationTime->format('Y-m-d H:i:s') : '未知';
            $result->addError('证书已被撤销，撤销时间: ' . $revocationTimeStr);
        } else {
            $result->addWarning('OCSP响应表明证书状态未知');
        }
        
        return $result;
    }
    
    /**
     * 生成缓存键
     *
     * @param X509Certificate $certificate 证书
     * @param X509Certificate $issuerCertificate 颁发者证书
     * @return string 缓存键
     */
    private function getCacheKey(X509Certificate $certificate, X509Certificate $issuerCertificate): string
    {
        return hash('sha256', $certificate->getSerialNumber() . $issuerCertificate->getSerialNumber());
    }
    
    /**
     * 设置连接超时时间
     *
     * @param int $timeout 连接超时时间（秒）
     * @return $this
     */
    public function setConnectTimeout(int $timeout): self
    {
        $this->connectTimeout = $timeout;
        return $this;
    }
    
    /**
     * 设置响应超时时间
     *
     * @param int $timeout 响应超时时间（秒）
     * @return $this
     */
    public function setResponseTimeout(int $timeout): self
    {
        $this->responseTimeout = $timeout;
        return $this;
    }
    
    /**
     * 设置是否使用随机数
     *
     * @param bool $useNonce 是否使用随机数
     * @return $this
     */
    public function setUseNonce(bool $useNonce): self
    {
        $this->useNonce = $useNonce;
        return $this;
    }
    
    /**
     * 清除响应缓存
     *
     * @return $this
     */
    public function clearCache(): self
    {
        $this->responseCache = [];
        return $this;
    }
} 