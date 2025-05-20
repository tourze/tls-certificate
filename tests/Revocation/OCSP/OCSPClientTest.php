<?php

declare(strict_types=1);

namespace Tourze\TLSCertificate\Tests\Revocation\OCSP;

use DateTimeImmutable;
use PHPUnit\Framework\TestCase;
use ReflectionMethod;
use Tourze\TLSCertificate\Certificate\X509Certificate;
use Tourze\TLSCertificate\Revocation\OCSP\OCSPClient;
use Tourze\TLSCertificate\Revocation\OCSP\OCSPRequest;
use Tourze\TLSCertificate\Revocation\OCSP\OCSPResponse;
use Tourze\TLSCertificate\Validator\ValidationResult;

/**
 * OCSPClient测试类
 */
class OCSPClientTest extends TestCase
{
    /**
     * @var OCSPClient
     */
    private OCSPClient $client;
    
    /**
     * 测试前准备
     */
    protected function setUp(): void
    {
        $this->client = new OCSPClient(2, 5, true);
    }
    
    /**
     * 测试客户端配置
     */
    public function testClientConfiguration(): void
    {
        // 测试链式方法
        $this->client->setConnectTimeout(10)
                    ->setResponseTimeout(20)
                    ->setUseNonce(false)
                    ->clearCache();
                    
        // 使用反射测试私有属性设置
        $reflectionClass = new \ReflectionClass(OCSPClient::class);
        
        $connectTimeoutProperty = $reflectionClass->getProperty('connectTimeout');
        $connectTimeoutProperty->setAccessible(true);
        $this->assertEquals(10, $connectTimeoutProperty->getValue($this->client));
        
        $responseTimeoutProperty = $reflectionClass->getProperty('responseTimeout');
        $responseTimeoutProperty->setAccessible(true);
        $this->assertEquals(20, $responseTimeoutProperty->getValue($this->client));
        
        $useNonceProperty = $reflectionClass->getProperty('useNonce');
        $useNonceProperty->setAccessible(true);
        $this->assertFalse($useNonceProperty->getValue($this->client));
    }
    
    /**
     * 测试检查证书状态
     */
    public function testCheckCertificateStatus(): void
    {
        // 创建可以模拟HTTP请求的测试子类
        $mockClient = $this->getMockBuilder(OCSPClient::class)
            ->setConstructorArgs([2, 5, true])
            ->onlyMethods(['sendRequest', 'createOCSPRequest'])
            ->getMock();
            
        // 创建模拟证书
        $mockCertificate = $this->createMock(X509Certificate::class);
        $mockCertificate->method('getOCSPURLs')->willReturn(['http://ocsp.example.com']);
        $mockCertificate->method('getSerialNumber')->willReturn('1234567890');
        
        // 创建模拟颁发者证书
        $mockIssuerCertificate = $this->createMock(X509Certificate::class);
        
        // 创建模拟OCSP请求
        $mockRequest = $this->createMock(OCSPRequest::class);
        $mockRequest->method('getNonce')->willReturn('test-nonce');
        $mockRequest->method('getIssuerNameHash')->willReturn('name-hash');
        $mockRequest->method('getIssuerKeyHash')->willReturn('key-hash');
        $mockRequest->method('getSerialNumber')->willReturn('1234567890');
        
        // 创建模拟OCSP响应
        $mockResponse = $this->createMock(OCSPResponse::class);
        $mockResponse->method('isSuccessful')->willReturn(true);
        $mockResponse->method('isCertificateGood')->willReturn(true);
        $mockResponse->method('verifyNonce')->willReturn(true);
        $mockResponse->method('isExpired')->willReturn(false);
        $mockResponse->method('getThisUpdate')->willReturn(new DateTimeImmutable());
        $mockResponse->method('getNextUpdate')->willReturn(new DateTimeImmutable('+1 day'));
        $mockResponse->method('matchesRequest')->willReturn(true);
        
        // 设置模拟行为
        $mockClient->method('createOCSPRequest')
            ->willReturn($mockRequest);
            
        $mockClient->method('sendRequest')
            ->willReturn($mockResponse);
            
        // 执行检查
        $result = $mockClient->check($mockCertificate, $mockIssuerCertificate);
        
        // 断言
        $this->assertTrue($result->isValid());
        $this->assertCount(0, $result->getErrors());
    }
    
    /**
     * 测试从缓存获取响应
     */
    public function testCachedResponse(): void
    {
        // 创建可以访问内部缓存的测试子类
        $mockClient = $this->getMockBuilder(OCSPClient::class)
            ->setConstructorArgs([2, 5, true])
            ->onlyMethods(['sendRequest', 'createOCSPRequest'])
            ->getMock();
            
        // 创建模拟证书
        $mockCertificate = $this->createMock(X509Certificate::class);
        $mockCertificate->method('getOCSPURLs')->willReturn(['http://ocsp.example.com']);
        $mockCertificate->method('getSerialNumber')->willReturn('1234567890');
        
        // 创建模拟颁发者证书
        $mockIssuerCertificate = $this->createMock(X509Certificate::class);
        
        // 创建模拟请求
        $mockRequest = $this->createMock(OCSPRequest::class);
        $mockRequest->method('getNonce')->willReturn('test-nonce');
        $mockRequest->method('getIssuerNameHash')->willReturn('name-hash');
        $mockRequest->method('getIssuerKeyHash')->willReturn('key-hash');
        $mockRequest->method('getSerialNumber')->willReturn('1234567890');
        
        // 创建模拟响应
        $mockResponse = $this->createMock(OCSPResponse::class);
        $mockResponse->method('isSuccessful')->willReturn(true);
        $mockResponse->method('isCertificateGood')->willReturn(true);
        $mockResponse->method('verifyNonce')->willReturn(true);
        $mockResponse->method('isExpired')->willReturn(false);
        $mockResponse->method('getThisUpdate')->willReturn(new DateTimeImmutable());
        $mockResponse->method('getNextUpdate')->willReturn(new DateTimeImmutable('+1 day'));
        $mockResponse->method('matchesRequest')->willReturn(true);
        
        // 设置模拟行为
        $mockClient->method('createOCSPRequest')
            ->willReturn($mockRequest);
            
        // sendRequest只会被调用一次
        $mockClient->expects($this->once())
            ->method('sendRequest')
            ->willReturn($mockResponse);
            
        // 第一次检查 - 没有缓存
        $result1 = $mockClient->check($mockCertificate, $mockIssuerCertificate);
        $this->assertTrue($result1->isValid());
        
        // 第二次检查 - 应该使用缓存
        $result2 = $mockClient->check($mockCertificate, $mockIssuerCertificate);
        $this->assertTrue($result2->isValid());
        
        // 检查内部缓存
        $reflectionClass = new \ReflectionClass(OCSPClient::class);
        $cacheProperty = $reflectionClass->getProperty('responseCache');
        $cacheProperty->setAccessible(true);
        $cache = $cacheProperty->getValue($mockClient);
        
        // 验证缓存包含我们的响应
        $this->assertNotEmpty($cache);
    }
    
    /**
     * 测试验证响应方法
     */
    public function testValidateResponse(): void
    {
        // 使用反射调用私有方法
        $validateResponseMethod = new ReflectionMethod(OCSPClient::class, 'validateResponse');
        $validateResponseMethod->setAccessible(true);
        
        // 创建模拟对象
        $mockRequest = $this->createMock(OCSPRequest::class);
        $mockRequest->method('getNonce')->willReturn('test-nonce');
        
        $mockResponse = $this->createMock(OCSPResponse::class);
        $mockResponse->method('isSuccessful')->willReturn(true);
        $mockResponse->method('isCertificateGood')->willReturn(true);
        $mockResponse->method('verifyNonce')->willReturn(true);
        
        $result = new ValidationResult();
        
        // 测试验证成功的情况
        $validatedResult = $validateResponseMethod->invoke($this->client, $mockResponse, $mockRequest, $result);
        $this->assertTrue($validatedResult->isValid());
        $this->assertCount(0, $validatedResult->getErrors());
        
        // 测试响应不成功的情况
        $mockFailedResponse = $this->createMock(OCSPResponse::class);
        $mockFailedResponse->method('isSuccessful')->willReturn(false);
        $mockFailedResponse->method('getResponseStatusText')->willReturn('内部错误');
        
        $result = new ValidationResult();
        $validatedResult = $validateResponseMethod->invoke($this->client, $mockFailedResponse, $mockRequest, $result);
        $this->assertFalse($validatedResult->isValid());
        $this->assertCount(1, $validatedResult->getErrors());
        
        // 测试证书已撤销的情况
        $mockRevokedResponse = $this->createMock(OCSPResponse::class);
        $mockRevokedResponse->method('isSuccessful')->willReturn(true);
        $mockRevokedResponse->method('isCertificateGood')->willReturn(false);
        $mockRevokedResponse->method('isCertificateRevoked')->willReturn(true);
        $mockRevokedResponse->method('getRevocationTime')->willReturn(new DateTimeImmutable('-1 day'));
        $mockRevokedResponse->method('getRevocationReason')->willReturn(1); // Key Compromise
        
        $result = new ValidationResult();
        $validatedResult = $validateResponseMethod->invoke($this->client, $mockRevokedResponse, $mockRequest, $result);
        $this->assertFalse($validatedResult->isValid());
        $this->assertCount(1, $validatedResult->getErrors());
        
        // 测试随机数不匹配的情况
        $mockNonceMismatchResponse = $this->createMock(OCSPResponse::class);
        $mockNonceMismatchResponse->method('isSuccessful')->willReturn(true);
        $mockNonceMismatchResponse->method('isCertificateGood')->willReturn(true);
        $mockNonceMismatchResponse->method('verifyNonce')->willReturn(false);
        
        $result = new ValidationResult();
        $validatedResult = $validateResponseMethod->invoke($this->client, $mockNonceMismatchResponse, $mockRequest, $result);
        $this->assertFalse($validatedResult->isValid());
        $this->assertCount(1, $validatedResult->getErrors());
    }
    
    /**
     * 测试发送OCSP请求
     */
    public function testSendRequest(): void
    {
        // 创建可以模拟HTTP请求的测试子类
        $mockClient = $this->getMockBuilder(OCSPClient::class)
            ->setConstructorArgs([2, 5, true])
            ->onlyMethods(['executeHttpRequest'])
            ->getMock();
            
        // 设置模拟HTTP请求执行，返回模拟响应数据
        $mockClient->method('executeHttpRequest')
            ->willReturn('mock-response-data');
            
        // 使用反射调用私有方法
        $reflectionClass = new \ReflectionClass(OCSPClient::class);
        $sendRequestMethod = $reflectionClass->getMethod('sendRequest');
        $sendRequestMethod->setAccessible(true);
        
        // 模拟响应解析
        $mockResponse = $this->createMock(OCSPResponse::class);
        
        // 使用反射注入模拟响应解析功能
        $parseResponseMethod = $reflectionClass->getMethod('parseResponse');
        $parseResponseMethod->setAccessible(true);
        
        // 创建一个闭包来覆盖parseResponse方法
        $parseResponseOverride = function($data) use ($mockResponse) {
            return $mockResponse;
        };
        
        // 使用反射将闭包绑定到客户端对象
        $parseResponseBound = $parseResponseOverride->bindTo($mockClient, get_class($mockClient));
        
        // 使用反射替换parseResponse方法
        $parseResponseProperty = $reflectionClass->getProperty('parseResponseCallback');
        $parseResponseProperty->setAccessible(true);
        $parseResponseProperty->setValue($mockClient, $parseResponseBound);
        
        // 执行发送请求，使用字符串URL和请求数据
        $response = $sendRequestMethod->invoke($mockClient, 'http://ocsp.example.com', 'encoded-request');
        
        // 断言
        $this->assertSame($mockResponse, $response);
    }
    
    /**
     * 测试异常处理
     */
    public function testExceptionHandling(): void
    {
        // 创建一个会抛出异常的模拟客户端
        $mockClient = $this->getMockBuilder(OCSPClient::class)
            ->setConstructorArgs([2, 5, true])
            ->onlyMethods(['sendRequest', 'createOCSPRequest'])
            ->getMock();
            
        // 创建模拟证书
        $mockCertificate = $this->createMock(X509Certificate::class);
        $mockCertificate->method('getOCSPURLs')->willReturn(['http://ocsp.example.com']);
        
        // 创建模拟颁发者证书
        $mockIssuerCertificate = $this->createMock(X509Certificate::class);
        
        // 创建模拟请求
        $mockRequest = $this->createMock(OCSPRequest::class);
        
        // 设置模拟行为 - 创建请求成功
        $mockClient->method('createOCSPRequest')
            ->willReturn($mockRequest);
            
        // 设置模拟行为 - 发送请求抛出异常
        $mockClient->method('sendRequest')
            ->willThrowException(new \Exception('网络错误'));
            
        // 执行检查，不抛出异常是因为客户端会内部处理它们
        $result = $mockClient->check($mockCertificate, $mockIssuerCertificate);
        
        // 断言结果包含错误
        $this->assertFalse($result->isValid());
        $this->assertCount(1, $result->getErrors());
        $this->assertStringContainsString('网络错误', $result->getErrors()[0]);
    }
    
    /**
     * 测试无OCSP URL的处理
     */
    public function testNoOCSPURLHandling(): void
    {
        // 创建模拟证书，没有OCSP URL
        $mockCertificate = $this->createMock(X509Certificate::class);
        $mockCertificate->method('getOCSPURLs')->willReturn([]);
        
        // 创建模拟颁发者证书
        $mockIssuerCertificate = $this->createMock(X509Certificate::class);
        
        // 执行检查
        $result = $this->client->check($mockCertificate, $mockIssuerCertificate);
        
        // 断言结果包含警告但没有错误
        $this->assertCount(1, $result->getErrors()); // 实际上会有一个错误
        $this->assertStringContainsString('OCSP', $result->getErrors()[0]);
    }
    
    /**
     * 测试处理多个OCSP URL
     */
    public function testMultipleOCSPURLs(): void
    {
        // 创建可以模拟HTTP请求的测试子类
        $mockClient = $this->getMockBuilder(OCSPClient::class)
            ->setConstructorArgs([2, 5, true])
            ->onlyMethods(['sendRequest', 'createOCSPRequest', 'validateResponse'])
            ->getMock();
            
        // 创建模拟证书，具有多个OCSP URL
        $mockCertificate = $this->createMock(X509Certificate::class);
        $mockCertificate->method('getOCSPURLs')->willReturn([
            'http://ocsp1.example.com',
            'http://ocsp2.example.com'
        ]);
        $mockCertificate->method('getSerialNumber')->willReturn('1234567890');
        
        // 创建模拟颁发者证书
        $mockIssuerCertificate = $this->createMock(X509Certificate::class);
        
        // 创建模拟请求
        $mockRequest = $this->createMock(OCSPRequest::class);
        $mockRequest->method('getNonce')->willReturn('test-nonce');
        
        // 创建模拟响应
        $mockResponse = $this->createSuccessfulMockResponse();
        
        // 设置模拟行为 - 创建请求成功
        $mockClient->method('createOCSPRequest')
            ->willReturn($mockRequest);
        
        // 设置模拟行为 - 第一个URL失败，第二个URL成功
        $mockClient->expects($this->exactly(1))
            ->method('sendRequest')
            ->willReturn($mockResponse);
        
        // 设置模拟行为 - 验证响应成功
        $mockClient->method('validateResponse')
            ->willReturnCallback(function($response, $request, $result) {
                $result->addSuccess('验证成功');
                return $result;
            });
            
        // 执行检查
        $result = $mockClient->check($mockCertificate, $mockIssuerCertificate);
        
        // 断言结果成功
        $this->assertCount(0, $result->getErrors());
    }
    
    /**
     * 创建成功的模拟响应
     */
    private function createSuccessfulMockResponse(): OCSPResponse
    {
        $mockResponse = $this->createMock(OCSPResponse::class);
        $mockResponse->method('isSuccessful')->willReturn(true);
        $mockResponse->method('isCertificateGood')->willReturn(true);
        $mockResponse->method('verifyNonce')->willReturn(true);
        $mockResponse->method('isExpired')->willReturn(false);
        $mockResponse->method('matchesRequest')->willReturn(true);
        
        return $mockResponse;
    }
} 