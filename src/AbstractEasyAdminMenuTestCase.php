<?php

namespace Tourze\PHPUnitSymfonyWebTest;

use PHPUnit\Framework\Attributes\RunTestsInSeparateProcesses;
use Tourze\PHPUnitSymfonyKernelTest\AbstractIntegrationTestCase;

#[RunTestsInSeparateProcesses]
abstract class AbstractEasyAdminMenuTestCase extends AbstractIntegrationTestCase
{
    /**
     * 子类可以重写此方法添加自定义的 setUp 逻辑
     */
    protected function onSetUp(): void
    {
        // 默认实现为空，子类可以根据需要重写
    }
}
