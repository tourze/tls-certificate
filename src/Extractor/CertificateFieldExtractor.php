<?php

declare(strict_types=1);

namespace Tourze\TLSCertificate\Extractor;

use DateTimeImmutable;
use DateTimeZone;
use Tourze\TLSCertificate\Certificate\X509Certificate;
use Tourze\TLSCertificate\Exception\ExtractorException;

/**
 * 证书字段提取器
 * 
 * 负责从ASN.1结构中提取证书字段信息
 */
class CertificateFieldExtractor
{
    /**
     * OID到名称的映射
     */
    private const OID_MAP = [
        '2.5.4.3' => 'CN', // Common Name
        '2.5.4.4' => 'SN', // Surname
        '2.5.4.5' => 'serialNumber', // Serial Number
        '2.5.4.6' => 'C',  // Country
        '2.5.4.7' => 'L',  // Locality
        '2.5.4.8' => 'ST', // State/Province
        '2.5.4.9' => 'STREET', // Street
        '2.5.4.10' => 'O',  // Organization
        '2.5.4.11' => 'OU', // Organizational Unit
        '2.5.4.12' => 'T',  // Title
        '2.5.4.42' => 'GN', // Given Name
        '1.2.840.113549.1.9.1' => 'E', // Email Address
    ];
    
    /**
     * 从ASN.1结构中提取证书字段
     *
     * @param array $asn1Data ASN.1解析后的证书数据
     * @param X509Certificate $certificate 要填充的证书对象
     * @throws ExtractorException 如果提取失败
     */
    public function extractFields(array $asn1Data, X509Certificate $certificate): void
    {
        try {
            // 提取TBS证书部分
            $tbsCertificate = $asn1Data['tbsCertificate'] ?? null;
            if (!$tbsCertificate) {
                throw new ExtractorException('缺少tbsCertificate字段');
            }
            
            // 提取版本
            $version = ($tbsCertificate['version'] ?? 0) + 1; // ASN.1中版本0表示X.509v1
            $certificate->setVersion($version);
            
            // 提取序列号
            $serialNumber = $tbsCertificate['serialNumber'] ?? '';
            $certificate->setSerialNumber($serialNumber);
            
            // 提取签名算法
            $signatureAlgorithm = $asn1Data['signatureAlgorithm']['algorithm'] ?? '';
            $certificate->setSignatureAlgorithm($signatureAlgorithm);
            
            // 提取颁发者
            $issuerRdnSequence = $tbsCertificate['issuer']['rdnSequence'] ?? [];
            $issuer = $this->extractName($issuerRdnSequence);
            $certificate->setIssuer($issuer);
            
            // 提取主体
            $subjectRdnSequence = $tbsCertificate['subject']['rdnSequence'] ?? [];
            $subject = $this->extractName($subjectRdnSequence);
            $certificate->setSubject($subject);
            
            // 提取有效期
            $validity = $tbsCertificate['validity'] ?? [];
            if (isset($validity['notBefore']) && isset($validity['notAfter'])) {
                $notBefore = $this->parseTime($validity['notBefore']);
                $notAfter = $this->parseTime($validity['notAfter']);
                
                $certificate->setNotBefore($notBefore);
                $certificate->setNotAfter($notAfter);
            }
            
            // 提取公钥
            $publicKeyInfo = $tbsCertificate['subjectPublicKeyInfo'] ?? [];
            if (isset($publicKeyInfo['subjectPublicKey'])) {
                $certificate->setPublicKey($publicKeyInfo['subjectPublicKey']);
            }
            
            // 提取扩展字段（在实际实现中还需要处理）
            // 这里暂不实现扩展字段的提取
        } catch (ExtractorException $e) {
            throw $e;
        } catch (\Exception $e) {
            throw new ExtractorException('提取证书字段失败: ' . $e->getMessage(), 0, $e);
        }
    }
    
    /**
     * 从RDN序列中提取名称字段
     *
     * @param array $rdnSequence RDN序列
     * @return array 名称字段映射
     */
    private function extractName(array $rdnSequence): array
    {
        $result = [];
        
        foreach ($rdnSequence as $rdn) {
            foreach ($rdn as $attribute) {
                $type = $attribute['type'] ?? '';
                $value = $attribute['value'] ?? '';
                
                // 如果值是一个结构，尝试解码字符串
                if (is_array($value)) {
                    $value = $this->decodeString($value);
                }
                
                // 将OID映射为可读名称
                $name = self::OID_MAP[$type] ?? $type;
                
                $result[$name] = $value;
            }
        }
        
        return $result;
    }
    
    /**
     * 解析ASN.1中的时间格式
     *
     * @param string $time ASN.1格式的时间字符串
     * @return DateTimeImmutable 解析后的DateTime对象
     * @throws ExtractorException 如果解析失败
     */
    public function parseTime(string $time): DateTimeImmutable
    {
        try {
            // 检查是UTC时间还是通用时间
            // UTCTime: YYMMDDhhmmssZ
            // GeneralizedTime: YYYYMMDDhhmmssZ or YYYYMMDDhhmmss±hhmm
            
            $format = '';
            $dateString = '';
            $timeZoneOffset = '';
            
            if (preg_match('/^(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})Z$/', $time, $matches)) {
                // UTCTime格式
                [, $year, $month, $day, $hour, $minute, $second] = $matches;
                
                // 处理年份 (UTCTime中年份是2位，需要扩展为4位)
                // 根据RFC 5280，如果年份小于50，应该被解释为20xx年；如果大于或等于50，应该被解释为19xx年
                $year = (int)$year;
                $year = ($year >= 50) ? "19{$year}" : "20{$year}";
                
                $dateString = sprintf('%s-%s-%s %s:%s:%s', $year, $month, $day, $hour, $minute, $second);
                $format = 'Y-m-d H:i:s';
                
            } elseif (preg_match('/^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})Z$/', $time, $matches)) {
                // GeneralizedTime格式 (UTC)
                [, $year, $month, $day, $hour, $minute, $second] = $matches;
                $dateString = sprintf('%s-%s-%s %s:%s:%s', $year, $month, $day, $hour, $minute, $second);
                $format = 'Y-m-d H:i:s';
                
            } elseif (preg_match('/^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})([+-])(\d{2})(\d{2})$/', $time, $matches)) {
                // GeneralizedTime格式 (带时区)
                [, $year, $month, $day, $hour, $minute, $second, $tzSign, $tzHour, $tzMinute] = $matches;
                $dateString = sprintf('%s-%s-%s %s:%s:%s', $year, $month, $day, $hour, $minute, $second);
                $format = 'Y-m-d H:i:s';
                $timeZoneOffset = sprintf('%s%s:%s', $tzSign, $tzHour, $tzMinute);
            } else {
                throw new ExtractorException('无效的时间格式');
            }
            
            // 创建日期时间对象
            if ($timeZoneOffset) {
                // 带时区的时间
                $timezone = new DateTimeZone($timeZoneOffset);
                $dateTime = DateTimeImmutable::createFromFormat($format, $dateString, $timezone);
                // 转换为UTC
                return $dateTime->setTimezone(new DateTimeZone('UTC'));
            } else {
                // UTC时间
                $dateTime = DateTimeImmutable::createFromFormat($format, $dateString, new DateTimeZone('UTC'));
            }
            
            if ($dateTime === false) {
                throw new ExtractorException('日期时间解析失败');
            }
            
            return $dateTime;
        } catch (ExtractorException $e) {
            throw $e;
        } catch (\Exception $e) {
            throw new ExtractorException('时间解析失败: ' . $e->getMessage(), 0, $e);
        }
    }
    
    /**
     * 解码ASN.1字符串
     *
     * @param array $stringData 字符串数据
     * @return string 解码后的字符串
     */
    public function decodeString(array $stringData): string
    {
        $type = $stringData['type'] ?? '';
        $value = $stringData['value'] ?? '';
        
        // 不同类型的字符串编码解码
        switch ($type) {
            case 'utf8String':
                // UTF-8字符串
                return $value;
                
            case 'printableString':
                // PrintableString是ASCII字符的子集
                return $value;
                
            case 'ia5String':
                // IA5String是ASCII字符
                return $value;
                
            case 'bmpString':
                // BMPString是Unicode字符串
                // 实际实现可能需要进行转换
                return $value;
                
            case 'teletexString':
            case 't61String':
                // T61/Teletex字符串
                // 这些可能需要特殊处理
                return $value;
                
            default:
                // 对于未知类型，直接返回值
                return (string)$value;
        }
    }
}
