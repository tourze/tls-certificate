<?php

declare(strict_types=1);

namespace Tourze\TLSCertificate\Tests\Revocation\CRL;

use DateTimeImmutable;
use PHPUnit\Framework\TestCase;
use Tourze\TLSCertificate\Certificate\X509Certificate;
use Tourze\TLSCertificate\Crypto\SignatureVerifier;
use Tourze\TLSCertificate\Revocation\CRL\CertificateRevocationList;
use Tourze\TLSCertificate\Revocation\CRL\CRLEntry;
use Tourze\TLSCertificate\Revocation\CRL\CRLValidator;

/**
 * CRLValidator测试类
 */
class CRLValidatorTest extends TestCase
{
    /**
     * @var CRLValidator
     */
    private CRLValidator $validator;
    
    /**
     * @var SignatureVerifier|\PHPUnit\Framework\MockObject\MockObject
     */
    private $mockSignatureVerifier;
    
    /**
     * 测试前准备
     */
    protected function setUp(): void
    {
        $this->mockSignatureVerifier = $this->createMock(SignatureVerifier::class);
        $this->validator = new CRLValidator($this->mockSignatureVerifier);
    }
    
    /**
     * 测试验证有效的CRL
     */
    public function testValidateValidCRL(): void
    {
        // 创建模拟的颁发者证书
        $mockIssuerCert = $this->createMock(X509Certificate::class);
        $mockIssuerCert->method('getSubjectDN')->willReturn('CN=Test CA Issuer');
        $mockIssuerCert->method('getPublicKey')->willReturn('mock-public-key');
        
        // 创建CRL
        $crl = new CertificateRevocationList(
            'CN=Test CA Issuer',
            new DateTimeImmutable('-1 day'),
            new DateTimeImmutable('+1 day'),
            '1',
            'sha256WithRSAEncryption',
            'mock-signature',
            'mock-raw-data'
        );
        
        // 设置模拟签名验证器行为
        $this->mockSignatureVerifier->method('verify')
            ->willReturn(true);
        
        // 验证CRL
        $result = $this->validator->validate($crl, $mockIssuerCert);
        
        // 断言
        $this->assertTrue($result->isValid());
        $this->assertCount(0, $result->getErrors());
    }
    
    /**
     * 测试验证签名无效的CRL
     */
    public function testValidateCRLWithInvalidSignature(): void
    {
        // 创建模拟的颁发者证书
        $mockIssuerCert = $this->createMock(X509Certificate::class);
        $mockIssuerCert->method('getSubjectDN')->willReturn('CN=Test CA Issuer');
        $mockIssuerCert->method('getPublicKey')->willReturn('mock-public-key');
        
        // 创建CRL
        $crl = new CertificateRevocationList(
            'CN=Test CA Issuer',
            new DateTimeImmutable('-1 day'),
            new DateTimeImmutable('+1 day'),
            '1',
            'sha256WithRSAEncryption',
            'mock-signature',
            'mock-raw-data'
        );
        
        // 设置模拟签名验证器行为，返回false表示签名无效
        $this->mockSignatureVerifier->method('verify')
            ->willReturn(false);
        
        // 验证CRL
        $result = $this->validator->validate($crl, $mockIssuerCert);
        
        // 断言
        $this->assertFalse($result->isValid());
        $this->assertCount(1, $result->getErrors());
        $this->assertStringContainsString('签名无效', $result->getErrors()[0]);
    }
    
    /**
     * 测试验证过期的CRL
     */
    public function testValidateExpiredCRL(): void
    {
        // 创建模拟的颁发者证书
        $mockIssuerCert = $this->createMock(X509Certificate::class);
        $mockIssuerCert->method('getSubjectDN')->willReturn('CN=Test CA Issuer');
        
        // 创建过期的CRL
        $crl = new CertificateRevocationList(
            'CN=Test CA Issuer',
            new DateTimeImmutable('-2 days'),
            new DateTimeImmutable('-1 day'),
            '1'
        );
        
        // 验证CRL
        $result = $this->validator->validate($crl, $mockIssuerCert);
        
        // 断言 - 过期应该产生警告但不是错误
        $this->assertTrue($result->isValid());
        $this->assertCount(0, $result->getErrors());
        $this->assertGreaterThan(0, $result->getWarnings());
    }
    
    /**
     * 测试验证尚未生效的CRL
     */
    public function testValidateNotYetValidCRL(): void
    {
        // 创建模拟的颁发者证书
        $mockIssuerCert = $this->createMock(X509Certificate::class);
        $mockIssuerCert->method('getSubjectDN')->willReturn('CN=Test CA Issuer');
        
        // 创建尚未生效的CRL
        $crl = new CertificateRevocationList(
            'CN=Test CA Issuer',
            new DateTimeImmutable('+1 day'),
            new DateTimeImmutable('+2 days'),
            '1'
        );
        
        // 验证CRL
        $result = $this->validator->validate($crl, $mockIssuerCert);
        
        // 断言 - 尚未生效应该是错误
        $this->assertFalse($result->isValid());
        $this->assertCount(1, $result->getErrors());
    }
    
    /**
     * 测试验证颁发者不匹配的CRL
     */
    public function testValidateCRLWithMismatchedIssuer(): void
    {
        // 创建模拟的颁发者证书，其主题与CRL颁发者不匹配
        $mockIssuerCert = $this->createMock(X509Certificate::class);
        $mockIssuerCert->method('getSubjectDN')->willReturn('CN=Different Issuer');
        
        // 创建CRL
        $crl = new CertificateRevocationList(
            'CN=Test CA Issuer',
            new DateTimeImmutable(),
            new DateTimeImmutable('+1 day'),
            '1'
        );
        
        // 验证CRL
        $result = $this->validator->validate($crl, $mockIssuerCert);
        
        // 断言
        $this->assertFalse($result->isValid());
        $this->assertCount(1, $result->getErrors());
    }
    
    /**
     * 测试检查证书撤销状态 - 未撤销
     */
    public function testCheckRevocationNotRevoked(): void
    {
        // 创建模拟的颁发者证书
        $mockIssuerCert = $this->createMock(X509Certificate::class);
        $mockIssuerCert->method('getSubjectDN')->willReturn('CN=Test CA Issuer');
        
        // 创建模拟的被检查证书
        $mockCertificate = $this->createMock(X509Certificate::class);
        $mockCertificate->method('getSerialNumber')->willReturn('123456');
        
        // 创建CRL
        $crl = new CertificateRevocationList(
            'CN=Test CA Issuer',
            new DateTimeImmutable(),
            new DateTimeImmutable('+1 day'),
            '1'
        );
        $crl->setIssuerCertificate($mockIssuerCert);
        
        // 验证证书未被撤销
        $result = $this->validator->checkRevocation($mockCertificate, $crl);
        
        // 断言
        $this->assertTrue($result->isValid());
        $this->assertCount(0, $result->getErrors());
    }
    
    /**
     * 测试检查证书撤销状态 - 已撤销
     */
    public function testCheckRevocationRevoked(): void
    {
        // 创建模拟的颁发者证书
        $mockIssuerCert = $this->createMock(X509Certificate::class);
        $mockIssuerCert->method('getSubjectDN')->willReturn('CN=Test CA Issuer');
        
        // 创建模拟的被检查证书
        $mockCertificate = $this->createMock(X509Certificate::class);
        $mockCertificate->method('getSerialNumber')->willReturn('123456');
        
        // 创建CRL
        $crl = new CertificateRevocationList(
            'CN=Test CA Issuer',
            new DateTimeImmutable(),
            new DateTimeImmutable('+1 day'),
            '1'
        );
        $crl->setIssuerCertificate($mockIssuerCert);
        
        // 添加撤销条目
        $revokedEntry = new CRLEntry(
            '123456',
            new DateTimeImmutable('-1 day'),
            1 // CRLReason::KEY_COMPROMISE
        );
        $crl->addRevokedCertificate($revokedEntry);
        
        // 验证证书撤销状态
        $result = $this->validator->checkRevocation($mockCertificate, $crl);
        
        // 断言
        $this->assertFalse($result->isValid());
        $this->assertCount(1, $result->getErrors());
    }
    
    /**
     * 测试检查证书撤销状态 - 已撤销但有移除标志
     */
    public function testCheckRevocationWithRemoveFromCRL(): void
    {
        // 创建模拟的颁发者证书
        $mockIssuerCert = $this->createMock(X509Certificate::class);
        $mockIssuerCert->method('getSubjectDN')->willReturn('CN=Test CA Issuer');
        
        // 创建模拟的被检查证书
        $mockCertificate = $this->createMock(X509Certificate::class);
        $mockCertificate->method('getSerialNumber')->willReturn('123456');
        
        // 创建CRL
        $crl = new CertificateRevocationList(
            'CN=Test CA Issuer',
            new DateTimeImmutable(),
            new DateTimeImmutable('+1 day'),
            '1'
        );
        $crl->setIssuerCertificate($mockIssuerCert);
        
        // 添加带有移除标志的撤销条目
        $revokedEntry = new CRLEntry(
            '123456',
            new DateTimeImmutable('-1 day'),
            8 // CRLReason::REMOVE_FROM_CRL
        );
        $crl->addRevokedCertificate($revokedEntry);
        
        // 验证证书撤销状态
        $result = $this->validator->checkRevocation($mockCertificate, $crl);
        
        // 断言 - 应该是有效的，因为REMOVE_FROM_CRL表示证书已从CRL中移除
        $this->assertTrue($result->isValid());
        $this->assertCount(0, $result->getErrors());
    }
    
    /**
     * 测试CRL与证书颁发者不匹配的情况
     */
    public function testCheckRevocationWithMismatchedIssuer(): void
    {
        // 创建模拟的颁发者证书
        $mockIssuerCert = $this->createMock(X509Certificate::class);
        $mockIssuerCert->method('getSubjectDN')->willReturn('CN=Test CA Issuer');
        
        // 创建模拟的被检查证书
        $mockCertificate = $this->createMock(X509Certificate::class);
        $mockCertificate->method('getSerialNumber')->willReturn('123456');
        $mockCertificate->method('getIssuerDN')->willReturn('CN=Different Issuer');
        
        // 创建CRL
        $crl = new CertificateRevocationList(
            'CN=Test CA Issuer',
            new DateTimeImmutable(),
            new DateTimeImmutable('+1 day'),
            '1'
        );
        $crl->setIssuerCertificate($mockIssuerCert);
        
        // 验证证书撤销状态
        $result = $this->validator->checkRevocation($mockCertificate, $crl);
        
        // 断言 - 由于颁发者不匹配，应返回警告而非错误
        $this->assertTrue($result->isValid());
        $this->assertCount(0, $result->getErrors());
        $this->assertGreaterThan(0, $result->getWarnings());
    }
} 