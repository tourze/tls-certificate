<?php

declare(strict_types=1);

namespace Tourze\TLSCertificate\Tests\Revocation;

use PHPUnit\Framework\TestCase;
use Tourze\TLSCertificate\Revocation\RevocationPolicy;

class RevocationPolicyTest extends TestCase
{
    public function test_policyValues_areCorrect(): void
    {
        $this->assertEquals('soft_fail', RevocationPolicy::SOFT_FAIL->value);
        $this->assertEquals('hard_fail', RevocationPolicy::HARD_FAIL->value);
        $this->assertEquals('crl_only', RevocationPolicy::CRL_ONLY->value);
        $this->assertEquals('ocsp_only', RevocationPolicy::OCSP_ONLY->value);
        $this->assertEquals('ocsp_preferred', RevocationPolicy::OCSP_PREFERRED->value);
        $this->assertEquals('crl_preferred', RevocationPolicy::CRL_PREFERRED->value);
        $this->assertEquals('disabled', RevocationPolicy::DISABLED->value);
    }
    
    public function test_policyEnum_canBeUsedInSwitch(): void
    {
        $policy = RevocationPolicy::OCSP_PREFERRED;
        
        $result = match($policy) {
            RevocationPolicy::SOFT_FAIL => 'soft_fail',
            RevocationPolicy::HARD_FAIL => 'hard_fail',
            RevocationPolicy::CRL_ONLY => 'crl_only',
            RevocationPolicy::OCSP_ONLY => 'ocsp_only',
            RevocationPolicy::OCSP_PREFERRED => 'ocsp_preferred',
            RevocationPolicy::CRL_PREFERRED => 'crl_preferred',
            RevocationPolicy::DISABLED => 'disabled',
        };
        
        $this->assertEquals('ocsp_preferred', $result);
    }
    
    public function test_policyEnum_canBeComparedDirectly(): void
    {
        $policy = RevocationPolicy::OCSP_PREFERRED;
        
        $this->assertTrue($policy === RevocationPolicy::OCSP_PREFERRED);
        $this->assertFalse($policy === RevocationPolicy::CRL_ONLY);
    }
} 