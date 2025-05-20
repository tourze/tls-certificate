<?php

declare(strict_types=1);

namespace Tourze\TLSCertificate\Tests\Revocation\CRL;

use DateTimeImmutable;
use PHPUnit\Framework\TestCase;
use Tourze\TLSCertificate\Certificate\X509Certificate;
use Tourze\TLSCertificate\Exception\CRLException;
use Tourze\TLSCertificate\Revocation\CRL\CertificateRevocationList;
use Tourze\TLSCertificate\Revocation\CRL\CRLEntry;
use Tourze\TLSCertificate\Revocation\CRL\CRLParser;

/**
 * CRLParser测试类
 */
class CRLParserTest extends TestCase
{
    /**
     * @var CRLParser
     */
    private CRLParser $parser;
    
    /**
     * 测试前准备
     */
    protected function setUp(): void
    {
        $this->parser = new CRLParser();
    }
    
    /**
     * 测试解析有效的PEM格式CRL
     */
    public function testParsePEM(): void
    {
        // 创建模拟解析器
        $parserMock = $this->getMockBuilder(CRLParser::class)
            ->onlyMethods(['parseDER'])
            ->getMock();
        
        // 创建模拟的CRL对象
        $mockCRL = $this->createMock(CertificateRevocationList::class);
        $mockCRL->method('getIssuerDN')->willReturn('Test CA Issuer');
        $mockCRL->method('getRevokedCertificates')->willReturn([
            'serial1' => new CRLEntry('serial1', new DateTimeImmutable(), 1),
            'serial2' => new CRLEntry('serial2', new DateTimeImmutable(), 4)
        ]);
        
        // 设置模拟行为
        $parserMock->expects($this->once())
            ->method('parseDER')
            ->willReturn($mockCRL);
        
        // 创建有效的PEM格式CRL数据
        $pemData = <<<EOD
-----BEGIN X509 CRL-----
MIIBjTCCAQEwCQYHKoZIzj0EATAaMRgwFgYDVQQDDA9UZXN0IENBIElzc3VlcjEX
DBUyMDIzMTIwMTAwMDAwMFoMFTIwMjQxMjAxMDAwMDAwWjB8MGICAQEXDTIzMTIw
MTAwMDAwMFowLjAsMAoGA1UdFQQDCgEBMB4GA1UdHgEB/wQUMBKgEDAOMQwwCgYD
VQQDDANmb28wIgIBAhcNMjMxMjAxMDAwMDAwWjAQMA4GA1UdFQQHCgEEMAGdZTAJ
BgcqhkjOPQQBA0kAMEYCIQDc+qwyxp1TYL63e+rDL0jQQfmOJ2Yj72F8tzIFbmwq
HwIhAIwEYFDy2ksJi1Z+HjxKLNTg3nwf8rYXZRCGf5zJzKX2
-----END X509 CRL-----
EOD;
        
        // 解析CRL
        $crl = $parserMock->parsePEM($pemData);
        
        // 断言
        $this->assertInstanceOf(CertificateRevocationList::class, $crl);
        $this->assertEquals('Test CA Issuer', $crl->getIssuerDN());
        $this->assertCount(2, $crl->getRevokedCertificates());
    }
    
    /**
     * 测试解析无效的PEM格式CRL
     */
    public function testParsePEMWithInvalidFormat(): void
    {
        $this->expectException(CRLException::class);
        
        // 创建无效的PEM格式数据
        $invalidPem = "Invalid PEM Data";
        
        // 尝试解析，预期抛出异常
        $this->parser->parsePEM($invalidPem);
    }
    
    /**
     * 测试解析带有无效Base64编码的PEM格式CRL
     */
    public function testParsePEMWithInvalidBase64(): void
    {
        $this->expectException(CRLException::class);
        
        // 创建带有无效Base64编码的PEM格式数据
        $invalidBase64Pem = <<<EOD
-----BEGIN X509 CRL-----
!@#$%^&*()_+Invalid Base64 Data
-----END X509 CRL-----
EOD;
        
        // 尝试解析，预期抛出异常
        $this->parser->parsePEM($invalidBase64Pem);
    }
    
    /**
     * 测试解析DER格式CRL
     */
    public function testParseDER(): void
    {
        // 模拟DER数据
        $derData = base64_decode('MIIBjTCCAQEwCQYHKoZIzj0EATAaMRgwFgYDVQQDDA9UZXN0IENBIElzc3VlcjEXDBUyMDIzMTIwMTAwMDAwMFoMFTIwMjQxMjAxMDAwMDAwWjB8MGICAQEXDTIzMTIwMTAwMDAwMFowLjAsMAoGA1UdFQQDCgEBMB4GA1UdHgEB/wQUMBKgEDAOMQwwCgYDVQQDDANmb28wIgIBAhcNMjMxMjAxMDAwMDAwWjAQMA4GA1UdFQQHCgEEMAGdZTAJBgcqhkjOPQQBA0kAMEYCIQDc+qwyxp1TYL63e+rDL0jQQfmOJ2Yj72F8tzIFbmwqHwIhAIwEYFDy2ksJi1Z+HjxKLNTg3nwf8rYXZRCGf5zJzKX2', true);
        
        // 使用模拟来避免实际执行openssl命令
        $parserMock = $this->getMockBuilder(CRLParser::class)
            ->onlyMethods(['executeOpenSSLCommand'])
            ->getMock();
        
        $parserMock->method('executeOpenSSLCommand')
            ->willReturn([
                'issuer' => 'Test CA Issuer',
                'lastUpdate' => '2023-12-01 00:00:00',
                'nextUpdate' => '2024-12-01 00:00:00',
                'signatureAlgorithm' => 'ecdsa-with-SHA256',
                'crlNumber' => '1',
                'revoked' => [
                    [
                        'serialNumber' => '01',
                        'revocationDate' => '2023-12-01 00:00:00',
                        'reasonCode' => 'Key Compromise'
                    ],
                    [
                        'serialNumber' => '02',
                        'revocationDate' => '2023-12-01 00:00:00',
                        'reasonCode' => 'Superseded'
                    ]
                ]
            ]);
        
        $crl = $parserMock->parseDER($derData);
        
        $this->assertInstanceOf(CertificateRevocationList::class, $crl);
        $this->assertEquals('Test CA Issuer', $crl->getIssuerDN());
        $this->assertCount(2, $crl->getRevokedCertificates());
        $this->assertEquals('ecdsa-with-SHA256', $crl->getSignatureAlgorithm());
    }
    
    /**
     * 测试从URL获取CRL
     */
    public function testFetchFromURL(): void
    {
        // 使用模拟HTTP请求
        $parserMock = $this->getMockBuilder(CRLParser::class)
            ->onlyMethods(['fetchData', 'parsePEM', 'parseDER'])
            ->getMock();
        
        // 模拟从URL获取数据
        $parserMock->method('fetchData')
            ->willReturn("-----BEGIN X509 CRL-----\nMockCRLData\n-----END X509 CRL-----");
        
        // 模拟PEM解析
        $mockCRL = $this->createMock(CertificateRevocationList::class);
        $parserMock->method('parsePEM')
            ->willReturn($mockCRL);
        
        $result = $parserMock->fetchFromURL('https://example.com/crl.pem');
        
        $this->assertSame($mockCRL, $result);
    }
    
    /**
     * 测试从URL获取CRL失败
     */
    public function testFetchFromURLFailed(): void
    {
        $this->expectException(CRLException::class);
        
        $parserMock = $this->getMockBuilder(CRLParser::class)
            ->onlyMethods(['fetchData'])
            ->getMock();
        
        // 模拟获取数据失败
        $parserMock->method('fetchData')
            ->willThrowException(new \Exception('Network error'));
        
        $parserMock->fetchFromURL('https://example.com/crl.pem');
    }
    
    /**
     * 测试提取CRL分发点
     */
    public function testExtractCRLDistributionPoints(): void
    {
        // 创建模拟证书
        $certificateMock = $this->createMock(X509Certificate::class);
        $certificateMock->method('getCRLDistributionPoints')
            ->willReturn(['http://example.com/crl.pem', 'http://backup.example.com/crl.pem']);
        
        $distributionPoints = $this->parser->extractCRLDistributionPoints($certificateMock);
        
        $this->assertIsArray($distributionPoints);
        $this->assertCount(2, $distributionPoints);
        $this->assertEquals('http://example.com/crl.pem', $distributionPoints[0]);
        $this->assertEquals('http://backup.example.com/crl.pem', $distributionPoints[1]);
    }
    
    /**
     * 测试从非X509Certificate对象提取CRL分发点
     */
    public function testExtractCRLDistributionPointsFromNonCertificate(): void
    {
        $nonCertificate = new \stdClass();
        
        $distributionPoints = $this->parser->extractCRLDistributionPoints($nonCertificate);
        
        $this->assertIsArray($distributionPoints);
        $this->assertEmpty($distributionPoints);
    }
} 