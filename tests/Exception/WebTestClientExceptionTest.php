<?php

namespace Tourze\PHPUnitSymfonyWebTest\Tests\Exception;

use PHPUnit\Framework\Attributes\CoversClass;
use Tourze\PHPUnitBase\AbstractExceptionTestCase;
use Tourze\PHPUnitSymfonyWebTest\Exception\WebTestClientException;

/**
 * @internal
 */
#[CoversClass(WebTestClientException::class)]
final class WebTestClientExceptionTest extends AbstractExceptionTestCase
{
    public function testExceptionExtendsRuntimeException(): void
    {
        $exception = new WebTestClientException('test message');

        self::assertEquals('test message', $exception->getMessage());
    }
}
