<?php

declare(strict_types=1);

namespace Tourze\TLSCertificate\Tests\Parser;

use PHPUnit\Framework\TestCase;
use Tourze\TLSCertificate\Certificate\X509Certificate;
use Tourze\TLSCertificate\Exception\ParserException;
use Tourze\TLSCertificate\Parser\CertificateParser;

/**
 * 证书解析器的测试类
 */
class CertificateParserTest extends TestCase
{
    /**
     * 测试PEM格式证书解析
     */
    public function testParsePEMCertificate(): void
    {
        // 创建一个测试用的PEM证书
        $pemCertificate = <<<EOT
-----BEGIN CERTIFICATE-----
MIIDazCCAlOgAwIBAgIUJQyU9aQpHqK8K+UDSt8UmJiExycwDQYJKoZIhvcNAQEL
BQAwRTELMAkGA1UEBhMCQVUxEzARBgNVBAgMClNvbWUtU3RhdGUxITAfBgNVBAoM
GEludGVybmV0IFdpZGdpdHMgUHR5IEx0ZDAeFw0yMjAxMDEwMDAwMDBaFw0yMzAx
MDEwMDAwMDBaMEUxCzAJBgNVBAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEw
HwYDVQQKDBhJbnRlcm5ldCBXaWRnaXRzIFB0eSBMdGQwggEiMA0GCSqGSIb3DQEB
AQUAA4IBDwAwggEKAoIBAQCz8y+jz7rY4QEJkCrYWn8wOCiDU/2xsD6lHVGh4THL
TsBPIjYXRx/o7ozE1QxzEqHLUmDJVRAOb+JGPeOzi9klPOb25y1u8qErwVdL4JsA
SJ4VZvbPI1baaNzL+p95KAm02Fpa/bUu7uPIK/zyVV5iF77pVRBZR8Z6HXWuqjmI
1hbXN1d/7xQbRmMHXEVcporfSBbvQxodDG9X8CtG4Cj3dJWxE/5SrHRGAJZkJJzT
Nn3GHJPnBmHEe20cVBG6sR3SN+bTz5nSL+ULKyiTIpw1FU7IG1Z56IepSZTRs5Pp
D/59SRmkD8QTmA8tNDhjxWJoJSDLdDEvN/WuQadlxvQDAgMBAAGjUzBRMB0GA1Ud
DgQWBBQeXcYFJfRwXX/U2MtDcxj7yQjGcTAfBgNVHSMEGDAWgBQeXcYFJfRwXX/U
2MtDcxj7yQjGcTAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQB+
d8JZo8RJkvvN1E1wUPCgAr6JYR6lCkJ7UUE9ISPcbL3K4HYw9TJf2axu/xI6DUhw
9xRnKAI+3VETASPo0Rd8mQB6orE0fB5u3C/jDQTKuuLEtC4PxWJ5Uac4FrWRBvRk
p5a5prs8vDUWRlE+S1YEV1iKOj7YQdXkOH5dNQ8nYPeWU3oPH2BZq/K4QFKz5XsG
wPrOCPq9n8cL9x3GuzuL6Pf1YJxfv3EqQzYiPvGQ924vRwUquFrVpBROS8bykJSv
ckaP8yEVbFVVGo6wd0s2xI5Jw3GG7hMrEcFCw2WYfV1vFrCqcGwYpzBdlcCeTIwR
zhV8cCQ98QJr5C9vF57z
-----END CERTIFICATE-----
EOT;

        $parser = new CertificateParser();
        $certificate = $parser->parsePEM($pemCertificate);
        
        $this->assertInstanceOf(X509Certificate::class, $certificate);
        $this->assertEquals(3, $certificate->getVersion());
        $this->assertEquals('Internet Widgits Pty Ltd', $certificate->getIssuer()['O']);
        $this->assertEquals('Internet Widgits Pty Ltd', $certificate->getSubject()['O']);
        
        // 检查日期是否正确解析
        $notBefore = $certificate->getNotBefore();
        $notAfter = $certificate->getNotAfter();
        
        $this->assertInstanceOf(\DateTimeImmutable::class, $notBefore);
        $this->assertInstanceOf(\DateTimeImmutable::class, $notAfter);
        
        $this->assertEquals('2022-01-01', $notBefore->format('Y-m-d'));
        $this->assertEquals('2023-01-01', $notAfter->format('Y-m-d'));
    }
    
    /**
     * 测试DER格式证书解析
     */
    public function testParseDERCertificate(): void
    {
        // 假设我们有一个DER格式的证书文件
        // 在实际测试中，我们需要准备一个真实的DER证书文件
        // 这里我们创建一个模拟的DER数据
        $derData = base64_decode('MIIDazCCAlOgAwIBAgIUJQyU9aQpHqK8K+UDSt8UmJiExycwDQYJKoZIhvcNAQELBQAwRTELMAkGA1UEBhMCQVUxEzARBgNVBAgMClNvbWUtU3RhdGUxITAfBgNVBAoMGEludGVybmV0IFdpZGdpdHMgUHR5IEx0ZDAeFw0yMjAxMDEwMDAwMDBaFw0yMzAxMDEwMDAwMDBaMEUxCzAJBgNVBAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEwHwYDVQQKDBhJbnRlcm5ldCBXaWRnaXRzIFB0eSBMdGQwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCz8y+jz7rY4QEJkCrYWn8wOCiDU/2xsD6lHVGh4THL');
        
        $parser = new CertificateParser();
        $certificate = $parser->parseDER($derData);
        
        $this->assertInstanceOf(X509Certificate::class, $certificate);
    }
    
    /**
     * 测试格式转换功能
     */
    public function testFormatConversion(): void
    {
        $pemCertificate = <<<EOT
-----BEGIN CERTIFICATE-----
MIIDazCCAlOgAwIBAgIUJQyU9aQpHqK8K+UDSt8UmJiExycwDQYJKoZIhvcNAQEL
BQAwRTELMAkGA1UEBhMCQVUxEzARBgNVBAgMClNvbWUtU3RhdGUxITAfBgNVBAoM
GEludGVybmV0IFdpZGdpdHMgUHR5IEx0ZDAeFw0yMjAxMDEwMDAwMDBaFw0yMzAx
MDEwMDAwMDBaMEUxCzAJBgNVBAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEw
HwYDVQQKDBhJbnRlcm5ldCBXaWRnaXRzIFB0eSBMdGQwggEiMA0GCSqGSIb3DQEB
AQUAA4IBDwAwggEKAoIBAQCz8y+jz7rY4QEJkCrYWn8wOCiDU/2xsD6lHVGh4THL
TsBPIjYXRx/o7ozE1QxzEqHLUmDJVRAOb+JGPeOzi9klPOb25y1u8qErwVdL4JsA
SJ4VZvbPI1baaNzL+p95KAm02Fpa/bUu7uPIK/zyVV5iF77pVRBZR8Z6HXWuqjmI
1hbXN1d/7xQbRmMHXEVcporfSBbvQxodDG9X8CtG4Cj3dJWxE/5SrHRGAJZkJJzT
Nn3GHJPnBmHEe20cVBG6sR3SN+bTz5nSL+ULKyiTIpw1FU7IG1Z56IepSZTRs5Pp
D/59SRmkD8QTmA8tNDhjxWJoJSDLdDEvN/WuQadlxvQDAgMBAAGjUzBRMB0GA1Ud
DgQWBBQeXcYFJfRwXX/U2MtDcxj7yQjGcTAfBgNVHSMEGDAWgBQeXcYFJfRwXX/U
2MtDcxj7yQjGcTAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQB+
d8JZo8RJkvvN1E1wUPCgAr6JYR6lCkJ7UUE9ISPcbL3K4HYw9TJf2axu/xI6DUhw
9xRnKAI+3VETASPo0Rd8mQB6orE0fB5u3C/jDQTKuuLEtC4PxWJ5Uac4FrWRBvRk
p5a5prs8vDUWRlE+S1YEV1iKOj7YQdXkOH5dNQ8nYPeWU3oPH2BZq/K4QFKz5XsG
wPrOCPq9n8cL9x3GuzuL6Pf1YJxfv3EqQzYiPvGQ924vRwUquFrVpBROS8bykJSv
ckaP8yEVbFVVGo6wd0s2xI5Jw3GG7hMrEcFCw2WYfV1vFrCqcGwYpzBdlcCeTIwR
zhV8cCQ98QJr5C9vF57z
-----END CERTIFICATE-----
EOT;

        $parser = new CertificateParser();
        
        // PEM -> DER
        $derData = $parser->pemToDer($pemCertificate);
        $this->assertNotEmpty($derData);
        
        // DER -> PEM
        $convertedPem = $parser->derToPem($derData);
        // 忽略空白字符比较
        $this->assertEquals(
            preg_replace('/\s+/', '', $pemCertificate),
            preg_replace('/\s+/', '', $convertedPem)
        );
    }
    
    /**
     * 测试无效输入的错误处理
     */
    public function testErrorHandling(): void
    {
        $parser = new CertificateParser();
        
        // 测试无效的PEM格式
        $this->expectException(ParserException::class);
        $this->expectExceptionMessage('无效的PEM格式证书');
        
        $parser->parsePEM('This is not a PEM certificate');
    }
}
