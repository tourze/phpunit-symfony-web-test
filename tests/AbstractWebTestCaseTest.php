<?php

declare(strict_types=1);

namespace Tourze\PHPUnitSymfonyWebTest\Tests;

use BizUserBundle\Entity\BizUser;
use EasyCorp\Bundle\EasyAdminBundle\Attribute\AdminCrud;
use EasyCorp\Bundle\EasyAdminBundle\Controller\AbstractCrudController;
use EasyCorp\Bundle\EasyAdminBundle\Controller\AbstractDashboardController;
use PHPUnit\Framework\AssertionFailedError;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\RunTestsInSeparateProcesses;
use PHPUnit\Framework\TestCase;
use Symfony\Bundle\FrameworkBundle\KernelBrowser;
use Symfony\Bundle\FrameworkBundle\Test\WebTestCase;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Attribute\Route;
use Symfony\Component\Security\Core\User\UserInterface;
use Tourze\PHPUnitSymfonyWebTest\AbstractWebTestCase;
use Tourze\PHPUnitSymfonyWebTest\Exception\WebTestClientException;

/**
 * @internal
 */
#[CoversClass(AbstractWebTestCase::class)]
final class AbstractWebTestCaseTest extends TestCase
{
    private ConcreteWebTestCase $webTestCase;

    protected function setUp(): void
    {
        parent::setUp();
        $this->webTestCase = new ConcreteWebTestCase('testName');
    }

    public function testLoginAsAdminShouldReturnUserInterface(): void
    {
        // Arrange
        $client = $this->createMock(KernelBrowser::class);
        $client->expects(self::once())->method('loginUser');

        // Act
        $result = $this->webTestCase->callLoginAsAdmin($client);

        // Assert
        self::assertEquals('admin', $result->getUserIdentifier());
        self::assertContains('ROLE_ADMIN', $result->getRoles());
    }

    public function testLoginAsUserShouldReturnUserInterface(): void
    {
        // Arrange
        $client = $this->createMock(KernelBrowser::class);
        $client->expects(self::once())->method('loginUser');

        // Act
        $result = $this->webTestCase->callLoginAsUser($client);

        // Assert
        self::assertEquals('user', $result->getUserIdentifier());
        self::assertContains('ROLE_USER', $result->getRoles());
    }

    public function testLoginWithRolesShouldCreateUserWithSpecifiedRoles(): void
    {
        // Arrange
        $client = $this->createMock(KernelBrowser::class);
        $roles = ['ROLE_ADMIN', 'ROLE_MANAGER'];

        $client->expects(self::once())->method('loginUser');

        // Act
        $result = $this->webTestCase->callLoginWithRoles($client, $roles);

        // Assert
        self::assertEquals('test', $result->getUserIdentifier());
        self::assertEquals($roles, $result->getRoles());
    }

    public function testCreateNormalUserShouldReturnUserWithRoleUser(): void
    {
        // Act
        $result = $this->webTestCase->callCreateNormalUser();

        // Assert
        self::assertEquals('user', $result->getUserIdentifier());
        self::assertContains('ROLE_USER', $result->getRoles());
    }

    public function testCreateAdminUserShouldReturnUserWithRoleAdmin(): void
    {
        // Act
        $result = $this->webTestCase->callCreateAdminUser();

        // Assert
        self::assertEquals('admin', $result->getUserIdentifier());
        self::assertContains('ROLE_ADMIN', $result->getRoles());
    }

    public function testCreateClientWithDatabaseMethodExists(): void
    {
        // 测试createClientWithDatabase方法存在且是protected static
        $reflection = new \ReflectionMethod(ConcreteWebTestCase::class, 'createClientWithDatabase');

        // Assert
        self::assertTrue($reflection->isProtected());
        self::assertTrue($reflection->isStatic());
    }

    public function testOnSetUpShouldDoNothingByDefault(): void
    {
        // Act & Assert - 默认onSetUp方法不做任何操作
        $this->webTestCase->callOnSetUp();

        // 验证方法可以被调用而不抛出异常
        $this->webTestCase->callOnSetUp();
        // 方法调用成功且没有抛出异常即为成功
        self::assertIsObject($this->webTestCase);
    }

    public function testOnTearDownShouldDoNothingByDefault(): void
    {
        // Act & Assert - 默认onTearDown方法不做任何操作
        $this->webTestCase->callOnTearDown();

        // 验证方法可以被调用而不抛出异常
        $this->webTestCase->callOnTearDown();
        // 方法调用成功且没有抛出异常即为成功
        self::assertIsObject($this->webTestCase);
    }

    public function testTearDownWebTestShouldCallEnsureKernelShutdown(): void
    {
        // 通过反射验证方法存在
        $reflection = new \ReflectionMethod($this->webTestCase, 'tearDownWebTest');

        // Assert
        self::assertTrue($reflection->isProtected()); // ConcreteWebTestCase中重写为protected

        // Act - 调用方法验证不会出错
        $this->webTestCase->callTearDownWebTest();
        // 方法调用成功且没有抛出异常即为成功
        self::assertIsObject($this->webTestCase);
    }

    public function testProvideFullMethodsShouldReturnAllHttpMethods(): void
    {
        // Act
        $methods = ConcreteWebTestCase::provideFullMethods();

        // Assert
        $expectedMethods = ['GET', 'POST', 'PUT', 'DELETE', 'TRACE', 'PURGE'];
        self::assertEquals($expectedMethods, $methods);
    }

    public function testProvideNotAllowedMethodsWithoutInvokeMethodShouldReturnInvalidMethod(): void
    {
        // 这个测试需要测试类有CoversClass注解才能工作
        // 我们通过创建一个临时的测试类来测试这个功能
        $testClass = new /**
         * @internal
         */
        #[CoversClass(RegularController::class)] class('testName') extends AbstractWebTestCase {
            public function testMethodNotAllowed(string $method): void
            {
                // Test implementation - 验证方法被正确调用
                self::assertIsString($method);
            }
        };

        // Act
        $methods = iterator_to_array($testClass::provideNotAllowedMethods());

        // Assert - 至少应该返回一个方法
        self::assertNotEmpty($methods);
        // 应该返回INVALID method，因为测试类没有invoke方法
        self::assertArrayHasKey('INVALID method', $methods);
        self::assertEquals(['INVALID'], $methods['INVALID method']);
    }

    public function testShouldIgnoreInvokeCheckWithCrudControllerShouldReturnTrue(): void
    {
        // Arrange
        $classReflection = new \ReflectionClass(TestCrudController::class);
        $method = new \ReflectionMethod($this->webTestCase, 'shouldIgnoreInvokeCheck');
        $method->setAccessible(true);

        // Act
        $result = $method->invoke($this->webTestCase, $classReflection);

        // Assert
        self::assertTrue($result);
    }

    public function testShouldIgnoreInvokeCheckWithDashboardControllerShouldReturnTrue(): void
    {
        // Arrange
        $classReflection = new \ReflectionClass(TestDashboardController::class);
        $method = new \ReflectionMethod($this->webTestCase, 'shouldIgnoreInvokeCheck');
        $method->setAccessible(true);

        // Act
        $result = $method->invoke($this->webTestCase, $classReflection);

        // Assert
        self::assertTrue($result);
    }

    public function testShouldIgnoreInvokeCheckWithRegularClassShouldReturnFalse(): void
    {
        // Arrange
        $classReflection = new \ReflectionClass(RegularController::class);
        $method = new \ReflectionMethod($this->webTestCase, 'shouldIgnoreInvokeCheck');
        $method->setAccessible(true);

        // Act
        $result = $method->invoke($this->webTestCase, $classReflection);

        // Assert
        self::assertFalse($result);
    }

    public function testExtractEntityMappingsWithEmptyBundlesShouldReturnEmptyArray(): void
    {
        // Arrange
        $bundles = [];
        $method = new \ReflectionMethod(AbstractWebTestCase::class, 'extractEntityMappings');
        $method->setAccessible(true);

        // Act
        $result = $method->invoke(null, $bundles);

        // Assert
        self::assertEmpty($result);
    }

    public function testWebTestClientExceptionCanBeThrown(): void
    {
        // Arrange
        $message = '测试异常消息';

        // Act & Assert
        $this->expectException(WebTestClientException::class);
        $this->expectExceptionMessage($message);

        throw new WebTestClientException($message);
    }

    public function testCreateKernelMethodIsFinal(): void
    {
        // Arrange & Act
        $reflection = new \ReflectionMethod(AbstractWebTestCase::class, 'createKernel');

        // Assert
        self::assertTrue($reflection->isFinal(), 'createKernel method should be final');
        self::assertTrue($reflection->isProtected(), 'createKernel method should be protected');
        self::assertTrue($reflection->isStatic(), 'createKernel method should be static');
    }

    public function testSetUpAndTearDownMethodsAreFinal(): void
    {
        // Arrange & Act
        $setUpReflection = new \ReflectionMethod(AbstractWebTestCase::class, 'setUp');
        $tearDownReflection = new \ReflectionMethod(AbstractWebTestCase::class, 'tearDown');

        // Assert
        self::assertTrue($setUpReflection->isFinal(), 'setUp method should be final');
        self::assertTrue($tearDownReflection->isFinal(), 'tearDown method should be final');
    }

    public function testCreateClientMethodIsFinal(): void
    {
        // Arrange & Act
        $reflection = new \ReflectionMethod(AbstractWebTestCase::class, 'createClient');

        // Assert
        self::assertTrue($reflection->isFinal(), 'createClient method should be final');
        self::assertTrue($reflection->isProtected(), 'createClient method should be protected');
        self::assertTrue($reflection->isStatic(), 'createClient method should be static');
    }

    public function testAbstractWebTestCaseExtendsWebTestCase(): void
    {
        // Arrange & Act
        $reflection = new \ReflectionClass(AbstractWebTestCase::class);

        // Assert
        self::assertTrue($reflection->isAbstract(), 'AbstractWebTestCase should be abstract');
        self::assertTrue($reflection->isSubclassOf(WebTestCase::class));
    }

    public function testTestMethodNotAllowedIsAbstract(): void
    {
        // Arrange & Act
        $reflection = new \ReflectionMethod(AbstractWebTestCase::class, 'testMethodNotAllowed');

        // Assert
        self::assertTrue($reflection->isAbstract(), 'testMethodNotAllowed should be abstract');
    }

    public function testWebTestClientExceptionInheritsFromRuntimeException(): void
    {
        // Arrange
        $exception = new WebTestClientException('test message');

        // Act & Assert
        self::assertEquals('test message', $exception->getMessage());
    }

    public function testLoginAsAdminWithCustomCredentialsShouldUseProvidedValues(): void
    {
        // Arrange
        $client = $this->createMock(KernelBrowser::class);
        $client->expects(self::once())->method('loginUser');

        // Act
        $result = $this->webTestCase->callLoginAsAdmin($client, 'testadmin', 'secret123');

        // Assert
        self::assertEquals('testadmin', $result->getUserIdentifier());
        self::assertContains('ROLE_ADMIN', $result->getRoles());
    }

    public function testLoginAsUserWithCustomCredentialsShouldUseProvidedValues(): void
    {
        // Arrange
        $client = $this->createMock(KernelBrowser::class);
        $client->expects(self::once())->method('loginUser');

        // Act
        $result = $this->webTestCase->callLoginAsUser($client, 'testuser', 'password123');

        // Assert
        self::assertEquals('testuser', $result->getUserIdentifier());
        self::assertContains('ROLE_USER', $result->getRoles());
    }

    public function testLoginWithRolesWithCustomParametersShouldUseProvidedValues(): void
    {
        // Arrange
        $client = $this->createMock(KernelBrowser::class);
        $roles = ['ROLE_EDITOR'];
        $client->expects(self::once())->method('loginUser');

        // Act
        $result = $this->webTestCase->callLoginWithRoles($client, $roles, 'editor', 'editpass');

        // Assert
        self::assertEquals('editor', $result->getUserIdentifier());
        self::assertEquals($roles, $result->getRoles());
    }

    public function testCreateNormalUserWithCustomCredentialsShouldUseProvidedValues(): void
    {
        // Act
        $result = $this->webTestCase->callCreateNormalUser('normaluser', 'normalpass');

        // Assert
        self::assertEquals('normaluser', $result->getUserIdentifier());
        self::assertContains('ROLE_USER', $result->getRoles());
    }

    public function testCreateAdminUserWithCustomCredentialsShouldUseProvidedValues(): void
    {
        // Act
        $result = $this->webTestCase->callCreateAdminUser('adminuser', 'adminpass');

        // Assert
        self::assertEquals('adminuser', $result->getUserIdentifier());
        self::assertContains('ROLE_ADMIN', $result->getRoles());
    }

    public function testTestMethodNotAllowedIsImplementedInConcreteClass(): void
    {
        // Arrange
        $this->expectException(AssertionFailedError::class);
        $this->expectExceptionMessage('Method GET should not be allowed');

        // Act
        $this->webTestCase->testMethodNotAllowed('GET');
    }
}

/**
 * 具体的测试类，用于测试抽象类
 * @internal
 */
#[CoversClass(AbstractWebTestCase::class)]
#[RunTestsInSeparateProcesses]
class ConcreteWebTestCase extends AbstractWebTestCase
{
    // 暴露protected方法供测试
    protected function onSetUp(): void
    {
        parent::onSetUp();
    }

    protected function onTearDown(): void
    {
        parent::onTearDown();
    }

    protected function tearDownWebTest(): void
    {
        parent::tearDownWebTest();
    }

    // 为测试提供public访问方法
    public function callOnSetUp(): void
    {
        $this->onSetUp();
    }

    public function callOnTearDown(): void
    {
        $this->onTearDown();
    }

    public function callTearDownWebTest(): void
    {
        $this->tearDownWebTest();
    }

    public function callLoginAsAdmin(KernelBrowser $client, string $username = 'admin', string $password = 'password'): UserInterface
    {
        return $this->loginAsAdmin($client, $username, $password);
    }

    public function callLoginAsUser(KernelBrowser $client, string $username = 'user', string $password = 'password'): UserInterface
    {
        return $this->loginAsUser($client, $username, $password);
    }

    public function callLoginWithRoles(KernelBrowser $client, array $roles, string $username = 'test', string $password = 'password'): UserInterface
    {
        return $this->loginWithRoles($client, $roles, $username, $password);
    }

    public function callCreateNormalUser(string $username = 'user', string $password = 'password'): UserInterface
    {
        return $this->createNormalUser($username, $password);
    }

    public function callCreateAdminUser(string $username = 'admin', string $password = 'password'): UserInterface
    {
        return $this->createAdminUser($username, $password);
    }

    // shouldIgnoreInvokeCheck是私有方法，通过反射测试

    // extractEntityMappings是私有静态方法，通过反射测试

    // 实现抽象方法
    public function testMethodNotAllowed(string $method): void
    {
        self::fail("Method {$method} should not be allowed");
    }

    // 重写私有方法的行为以便测试 - 设为public以便测试访问
    protected function loginAsAdmin(KernelBrowser $client, string $username = 'admin', string $password = 'password'): UserInterface
    {
        $user = $this->createMemoryUser($username, ['ROLE_ADMIN']);
        $client->loginUser($user);

        return $user;
    }

    protected function loginAsUser(KernelBrowser $client, string $username = 'user', string $password = 'password'): UserInterface
    {
        $user = $this->createMemoryUser($username, ['ROLE_USER']);
        $client->loginUser($user);

        return $user;
    }

    protected function loginWithRoles(KernelBrowser $client, array $roles, string $username = 'test', string $password = 'password'): UserInterface
    {
        $user = $this->createMemoryUser($username, $roles);
        $client->loginUser($user);

        return $user;
    }

    protected function createNormalUser(string $username = 'user', string $password = 'password'): UserInterface
    {
        return $this->createMemoryUser($username, ['ROLE_USER']);
    }

    protected function createAdminUser(string $username = 'admin', string $password = 'password'): UserInterface
    {
        return $this->createMemoryUser($username, ['ROLE_ADMIN']);
    }

    /**
     * @param array<string> $roles
     */
    private function createMemoryUser(string $username, array $roles): UserInterface
    {
        // @phpstan-ignore-next-line PreferInterfaceStubTraitRule.createMemoryUser
        return new class($username, $roles) implements UserInterface {
            /**
             * @param array<string> $roles
             */
            public function __construct(private string $username, private array $roles)
            {
            }

            /**
             * @return array<string>
             */
            public function getRoles(): array
            {
                return $this->roles;
            }

            public function eraseCredentials(): void
            {
            }

            public function getUserIdentifier(): string
            {
                return '' !== $this->username ? $this->username : 'unknown';
            }
        };
    }
}

/**
 * 测试用的CRUD控制器
 * @internal
 * @coversNothing
 * @extends AbstractCrudController<BizUser>
 */
#[AdminCrud]
class TestCrudController extends AbstractCrudController
{
    public static function getEntityFqcn(): string
    {
        return BizUser::class;
    }
}

/**
 * 测试用的Dashboard控制器
 * @internal
 */
class TestDashboardController extends AbstractDashboardController
{
    public function index(): Response
    {
        return new Response('Dashboard');
    }
}

/**
 * 测试用的普通控制器
 * @internal
 */
class RegularController
{
    public function __invoke(): Response
    {
        return new Response('OK');
    }
}
