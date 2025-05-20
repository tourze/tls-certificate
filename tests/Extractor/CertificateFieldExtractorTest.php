<?php

declare(strict_types=1);

namespace Tourze\TLSCertificate\Tests\Extractor;

use PHPUnit\Framework\TestCase;
use Tourze\TLSCertificate\Certificate\X509Certificate;
use Tourze\TLSCertificate\Exception\ExtractorException;
use Tourze\TLSCertificate\Extractor\CertificateFieldExtractor;

/**
 * 证书字段提取器的测试类
 */
class CertificateFieldExtractorTest extends TestCase
{
    /**
     * 测试从证书中提取基本字段
     */
    public function testExtractBasicFields(): void
    {
        // 创建一个假的ASN.1结构
        $certificateData = [
            'tbsCertificate' => [
                'version' => 2, // X.509v3
                'serialNumber' => '12345678',
                'signature' => [
                    'algorithm' => 'sha256WithRSAEncryption',
                ],
                'issuer' => [
                    'rdnSequence' => [
                        [['type' => '2.5.4.3', 'value' => 'Test CA']], // CN
                        [['type' => '2.5.4.10', 'value' => 'Test Organization']], // O
                    ],
                ],
                'validity' => [
                    'notBefore' => '220101000000Z', // 2022-01-01 00:00:00 UTC
                    'notAfter' => '230101000000Z', // 2023-01-01 00:00:00 UTC
                ],
                'subject' => [
                    'rdnSequence' => [
                        [['type' => '2.5.4.3', 'value' => 'example.com']], // CN
                        [['type' => '2.5.4.10', 'value' => 'Example Inc']], // O
                    ],
                ],
                'subjectPublicKeyInfo' => [
                    'algorithm' => [
                        'algorithm' => '1.2.840.113549.1.1.1', // RSA
                    ],
                    'subjectPublicKey' => 'TEST_PUBLIC_KEY',
                ],
            ],
            'signatureAlgorithm' => [
                'algorithm' => 'sha256WithRSAEncryption',
            ],
            'signature' => 'TEST_SIGNATURE',
        ];
        
        $extractor = new CertificateFieldExtractor();
        $certificate = new X509Certificate();
        
        $extractor->extractFields($certificateData, $certificate);
        
        // 验证字段是否正确提取
        $this->assertEquals(3, $certificate->getVersion());
        $this->assertEquals('12345678', $certificate->getSerialNumber());
        $this->assertEquals('sha256WithRSAEncryption', $certificate->getSignatureAlgorithm());
        
        // 验证名称字段
        $issuer = $certificate->getIssuer();
        $this->assertEquals('Test CA', $issuer['CN']);
        $this->assertEquals('Test Organization', $issuer['O']);
        
        $subject = $certificate->getSubject();
        $this->assertEquals('example.com', $subject['CN']);
        $this->assertEquals('Example Inc', $subject['O']);
        
        // 验证日期
        $notBefore = $certificate->getNotBefore();
        $notAfter = $certificate->getNotAfter();
        
        $this->assertInstanceOf(\DateTimeImmutable::class, $notBefore);
        $this->assertInstanceOf(\DateTimeImmutable::class, $notAfter);
        
        $this->assertEquals('2022-01-01', $notBefore->format('Y-m-d'));
        $this->assertEquals('2023-01-01', $notAfter->format('Y-m-d'));
    }
    
    /**
     * 测试时间和日期处理
     */
    public function testDateTimeProcessing(): void
    {
        $extractor = new CertificateFieldExtractor();
        
        // UTC时间格式
        $utcTime = '220101000000Z'; // 2022-01-01 00:00:00 UTC
        $dateTime = $extractor->parseTime($utcTime);
        
        $this->assertInstanceOf(\DateTimeImmutable::class, $dateTime);
        $this->assertEquals('2022-01-01', $dateTime->format('Y-m-d'));
        $this->assertEquals('00:00:00', $dateTime->format('H:i:s'));
        
        // 通用时间格式
        $generalizedTime = '20220101000000Z'; // 2022-01-01 00:00:00 UTC
        $dateTime = $extractor->parseTime($generalizedTime);
        
        $this->assertInstanceOf(\DateTimeImmutable::class, $dateTime);
        $this->assertEquals('2022-01-01', $dateTime->format('Y-m-d'));
        $this->assertEquals('00:00:00', $dateTime->format('H:i:s'));
        
        // 本地时间格式（带时区）
        $localTime = '20220101000000+0800'; // 2022-01-01 00:00:00 +0800
        $dateTime = $extractor->parseTime($localTime);
        
        $this->assertInstanceOf(\DateTimeImmutable::class, $dateTime);
        // 转换为UTC后应该是2021-12-31 16:00:00
        $this->assertEquals('2021-12-31 16:00:00', $dateTime->format('Y-m-d H:i:s'));
    }
    
    /**
     * 测试各种编码的处理
     */
    public function testEncodingHandling(): void
    {
        $extractor = new CertificateFieldExtractor();
        
        // 测试PrintableString编码
        $printableValue = 'Test String';
        $decodedValue = $extractor->decodeString(['type' => 'printableString', 'value' => $printableValue]);
        $this->assertEquals($printableValue, $decodedValue);
        
        // 测试UTF8String编码
        $utf8Value = '测试字符串';
        $decodedValue = $extractor->decodeString(['type' => 'utf8String', 'value' => $utf8Value]);
        $this->assertEquals($utf8Value, $decodedValue);
        
        // 测试IA5String编码 (ASCII)
        $ia5Value = 'email@example.com';
        $decodedValue = $extractor->decodeString(['type' => 'ia5String', 'value' => $ia5Value]);
        $this->assertEquals($ia5Value, $decodedValue);
    }
    
    /**
     * 测试异常情况
     */
    public function testExceptionHandling(): void
    {
        $extractor = new CertificateFieldExtractor();
        
        $this->expectException(ExtractorException::class);
        $this->expectExceptionMessage('无效的时间格式');
        
        $extractor->parseTime('invalid-time-format');
    }
}
