<?php

declare(strict_types=1);

namespace Tourze\PHPUnitSymfonyWebTest;

use EasyCorp\Bundle\EasyAdminBundle\Controller\AbstractCrudController;
use EasyCorp\Bundle\EasyAdminBundle\Controller\AbstractDashboardController;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Large;
use PHPUnit\Framework\Attributes\RunTestsInSeparateProcesses;
use PHPUnit\Framework\Attributes\Test;
use Symfony\Bundle\FrameworkBundle\FrameworkBundle;
use Symfony\Bundle\FrameworkBundle\KernelBrowser;
use Symfony\Bundle\FrameworkBundle\Test\WebTestCase as BaseWebTestCase;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Definition;
use Symfony\Component\DependencyInjection\Exception\ServiceNotFoundException;
use Symfony\Component\Dotenv\Dotenv;
use Symfony\Component\HttpKernel\KernelInterface;
use Symfony\Component\Routing\Attribute\Route;
use Symfony\Component\Security\Core\User\InMemoryUser;
use Symfony\Component\Security\Core\User\UserInterface;
use SymfonyTestingFramework\Kernel;
use Tourze\BundleDependency\ResolveHelper;
use Tourze\DoctrineResolveTargetEntityBundle\Testing\TestEntityGenerator;
use Tourze\PHPUnitBase\TestCaseHelper;
use Tourze\PHPUnitBase\TestHelper;
use Tourze\PHPUnitSymfonyKernelTest\BundleInferrer;
use Tourze\PHPUnitSymfonyKernelTest\DatabaseHelper;
use Tourze\PHPUnitSymfonyKernelTest\DoctrineTrait;
use Tourze\PHPUnitSymfonyKernelTest\EntityManagerHelper;
use Tourze\PHPUnitSymfonyKernelTest\Exception\DoctrineSupportException;
use Tourze\PHPUnitSymfonyKernelTest\InMemoryUserManager;
use Tourze\PHPUnitSymfonyKernelTest\ServiceLocatorTrait;
use Tourze\PHPUnitSymfonyWebTest\Exception\WebTestClientException;
use Tourze\UserServiceContracts\UserManagerInterface;

/**
 * 增强的 WebTestCase 基类
 *
 * 提供数据库管理、认证和其他常用测试功能
 * 完整的 EasyAdmin 集成环境
 */
#[Large]
abstract class AbstractWebTestCase extends BaseWebTestCase
{
    use DoctrineTrait;
    use ServiceLocatorTrait;

    /**
     * 以管理员身份登录
     */
    protected function loginAsAdmin(KernelBrowser $client, string $username = 'admin', string $password = 'password'): UserInterface
    {
        // 为兼容 testing framework 的内存用户提供者，这里固定使用 `admin`
        // 避免由于 provider 仅预置了 admin 用户而在请求时被刷新导致权限丢失
        return $this->loginWithMemoryUser($client, 'admin', ['ROLE_ADMIN']);
    }

    /**
     * 以普通用户身份登录
     */
    protected function loginAsUser(KernelBrowser $client, string $username = 'user', string $password = 'password'): UserInterface
    {
        $user = $this->findOrCreateUser($username, $password, ['ROLE_USER']);
        $client->loginUser($user);

        return $user;
    }

    /**
     * 以指定角色登录
     *
     * @param array<string> $roles
     */
    protected function loginWithRoles(KernelBrowser $client, array $roles, string $username = 'test', string $password = 'password'): UserInterface
    {
        $user = $this->findOrCreateUser($username, $password, $roles);
        $client->loginUser($user);

        return $user;
    }

    /**
     * 创建普通用户
     */
    protected function createNormalUser(string $username = 'user', string $password = 'password'): UserInterface
    {
        return $this->findOrCreateUser($username, $password, ['ROLE_USER']);
    }

    /**
     * 创建管理员用户
     */
    protected function createAdminUser(string $username = 'admin', string $password = 'password'): UserInterface
    {
        return $this->findOrCreateUser($username, $password, ['ROLE_ADMIN']);
    }

    /**
     * 查找或创建用户实体
     *
     * @param array<string> $roles
     */
    private function findOrCreateUser(string $username, string $password, array $roles): UserInterface
    {
        // 尝试查找已存在的用户
        $user = self::getService(UserManagerInterface::class)->loadUserByIdentifier($username);

        if (!$user) {
            $user = $this->createUser($username, $password, $roles);
        }

        return $user;
    }

    /**
     * 创建用户实体
     *
     * @param array<string> $roles
     */
    final protected function createUser(string $username, string $password, array $roles): UserInterface
    {
        $user = self::getService(UserManagerInterface::class)->createUser(
            userIdentifier: $username,
            password: $password,
            roles: $roles,
        );

        // 保存用户
        if (!$user instanceof InMemoryUser) {
            $this->persistAndFlush($user);
        }

        return $user;
    }

    /**
     * 持久化并刷新实体
     *
     * 便捷方法，同时执行 persist 和 flush
     *
     * @param bool $refresh 是否刷新实体状态
     */
    final protected function persistAndFlush(object $entity, bool $refresh = false): object
    {
        if (!self::hasDoctrineSupport()) {
            throw DoctrineSupportException::persistNotSupported();
        }

        $em = self::getEntityManager();
        $em->persist($entity);
        $em->flush();

        // 记录操作
        $this->getEntityManagerHelper()->recordOperation();

        if ($refresh) {
            $em->refresh($entity);
        }

        return $entity;
    }

    private ?EntityManagerHelper $entityManagerHelper = null;

    /**
     * 获取 EntityManager 辅助工具
     */
    private function getEntityManagerHelper(): EntityManagerHelper
    {
        if (null === $this->entityManagerHelper) {
            $this->entityManagerHelper = new EntityManagerHelper(self::getEntityManager());
        }

        return $this->entityManagerHelper;
    }

    /**
     * 使用内存用户登录（回退方案）
     *
     * @param array<string> $roles
     */
    private function loginWithMemoryUser(KernelBrowser $client, string $username, array $roles): UserInterface
    {
        // 使用框架内置的 InMemoryUser，避免匿名类导致的序列化失败
        $user = new InMemoryUser('' !== $username ? $username : 'unknown', '', $roles);
        $client->loginUser($user);

        return $user;
    }

    /**
     * 提取实体映射配置
     *
     * @param array<class-string, array<string, bool>> $bundles
     * @return array<string, string>
     */
    private static function extractEntityMappings(array $bundles): array
    {
        $entityMappings = [];

        // 如果 ResolveHelper 不可用，返回空数组
        if (!class_exists(ResolveHelper::class)) {
            return $entityMappings;
        }

        $resolvedBundles = ResolveHelper::resolveBundleDependencies($bundles);
        foreach ($resolvedBundles as $bundle => $env) {
            if (!class_exists($bundle)) {
                continue;
            }

            $reflection = new \ReflectionClass($bundle);
            $fileName = $reflection->getFileName();
            if (false === $fileName) {
                continue;
            }

            $entityPath = dirname($fileName) . '/Entity';
            if (is_dir($entityPath)) {
                $entityMappings[$reflection->getNamespaceName() . '\Entity'] = $entityPath;
            }
        }

        return $entityMappings;
    }

    protected function tearDownWebTest(): void
    {
        self::ensureKernelShutdown();
        DatabaseHelper::cleanupGeneratedDatabases();
    }

    /**
     * 子类可以重写此方法添加自定义的 setUp 逻辑
     */
    protected function onSetUp(): void
    {
        // 默认不做任何操作
    }

    /**
     * 子类可以重写此方法添加自定义的 tearDown 逻辑
     */
    protected function onTearDown(): void
    {
        // 默认不做任何操作
    }

    /**
     * 创建推断的Kernel（原有逻辑）
     * @param array<string, mixed> $options
     */
    private static function createInferredKernel(array $options): KernelInterface
    {
        $bundles = [
            FrameworkBundle::class => ['all' => true],
        ];

        // 自动推断当前测试类对应的 Bundle
        $bundleClass = BundleInferrer::inferBundleClass(get_called_class());
        if (null !== $bundleClass) {
            $bundles[$bundleClass] = ['all' => true];
        }

        // 查找所有关联Bundle，可能使用到的实体
        // 过滤出有效的类字符串
        /** @var array<class-string, array<string, bool>> $validBundles */
        $validBundles = [];
        foreach ($bundles as $bundle => $env) {
            if (class_exists($bundle)) {
                /** @var class-string $bundle */
                $validBundles[$bundle] = $env;
            }
        }
        $entityMappings = self::extractEntityMappings($validBundles);
        $projectDir = TestHelper::generateTempDir(get_called_class(), $bundles, $options, $entityMappings);

        // 临时生成的实体
        $entityGenerator = new TestEntityGenerator($projectDir);
        $entityMappings[$entityGenerator->getNamespace()] = $projectDir;

        DatabaseHelper::configureCacheContext(
            $projectDir,
            Kernel::class,
            $options['environment'] ?? 'test',
            [
                'mode' => 'web-inferred',
                'bundles' => array_keys($bundles),
            ]
        );
        $_ENV['DATABASE_URL'] = $_SERVER['DATABASE_URL'] = DatabaseHelper::generateUniqueDatabaseUrl();
        $_ENV['TRUSTED_PROXIES'] = $_SERVER['TRUSTED_PROXIES'] = '0.0.0.0/0';

        // 使用匿名类扩展测试 Kernel，在构建容器时补充默认的 UserManagerInterface
        return new class(environment: $options['environment'] ?? 'test', debug: $options['debug'] ?? true, projectDir: $projectDir, appendBundles: $bundles) extends Kernel {
            protected function build(ContainerBuilder $container): void
            {
                parent::build($container);

                // 如果没有显式提供 UserManagerInterface，则注册一个基于 InMemoryUser 的默认实现
                $id = UserManagerInterface::class;
                if (!$container->has($id) && !$container->hasDefinition($id) && !$container->hasAlias($id)) {
                    $definition = new Definition(InMemoryUserManager::class);
                    $definition->setPublic(true);
                    $container->setDefinition($id, $definition);
                }
            }
        };
    }

    /**
     * 不允许继承、覆盖这个方法
     * @param array<string, mixed> $options
     */
    final protected static function createKernel(array $options = []): KernelInterface
    {
        $dotenv = new Dotenv();
        $fileName = (new \ReflectionClass(get_called_class()))->getFileName();
        if (false === $fileName) {
            return self::createInferredKernel($options);
        }

        $dirName = $fileName;
        while ('/' !== $dirName) {
            $dirName = dirname($dirName);

            $envFile = "{$dirName}/.env.test";
            if (!is_file($envFile)) {
                continue;
            }

            $fileContents = \file_get_contents($envFile);
            if (false === $fileContents) {
                continue;
            }

            $env = $dotenv->parse($fileContents, $envFile);
            if (isset($env['KERNEL_CLASS'])) {
                $dotenv->populate($env, true);
                $kernelClass = $env['KERNEL_CLASS'];

                DatabaseHelper::configureCacheContext(
                    $dirName,
                    $kernelClass,
                    $options['environment'] ?? 'test',
                    ['mode' => 'web-project']
                );
                $_ENV['DATABASE_URL'] = $_SERVER['DATABASE_URL'] = DatabaseHelper::generateUniqueDatabaseUrl();
                $_ENV['TRUSTED_PROXIES'] = $_SERVER['TRUSTED_PROXIES'] = '0.0.0.0/0';

                if (!class_exists($kernelClass)) {
                    return self::createInferredKernel($options);
                }

                /** @var KernelInterface */
                return new $kernelClass($options['environment'] ?? 'test', $options['debug'] ?? true);
            }
        }

        return self::createInferredKernel($options);
    }

    /**
     * 创建内核浏览器
     * @param array<string, mixed> $options
     * @param array<string, mixed> $server
     */
    final protected static function createClient(array $options = [], array $server = []): KernelBrowser
    {
        if (static::$booted) {
            $client = self::getClient();
            if (null !== $client) {
                if (!$client instanceof KernelBrowser) {
                    throw new WebTestClientException('现有客户端不是 KernelBrowser 类型');
                }

                return $client;
            }
            // 如果客户端为null，继续创建新的客户端而不是抛异常
        }

        $kernel = static::bootKernel($options);

        try {
            $client = self::getContainer()->get('test.client');
            if (!$client instanceof KernelBrowser) {
                throw new WebTestClientException('无法创建功能测试客户端，请确保 "framework.test" 配置设置为 true');
            }
        } catch (ServiceNotFoundException) {
            if (class_exists(KernelBrowser::class)) {
                throw new WebTestClientException('无法创建功能测试客户端，请确保 "framework.test" 配置设置为 true');
            }
            throw new WebTestClientException('无法创建功能测试客户端，BrowserKit组件不可用，请运行 "composer require symfony/browser-kit"');
        }

        $client->setServerParameters($server);

        return $client;
    }

    /**
     * 初始化数据库并创建客户端
     *
     * 这个方法在测试中代替 createClient() 使用，
     * 以确保数据库在内核启动后被正确初始化
     *
     * 这个方法，我们关闭了异常捕捉，所以在控制器中抛出的异常，我们可以在测试用例中捕捉
     * @param array<string, mixed> $options
     * @param array<string, mixed> $server
     */
    protected static function createClientWithDatabase(array $options = [], array $server = []): KernelBrowser
    {
        $client = static::createClient($options, $server);

        // 如果有 Doctrine 支持，默认清理数据库
        if (self::hasDoctrineSupport()) {
            self::cleanDatabase();
        }

        $client->catchExceptions(false);

        return $client;
    }

    final protected function setUp(): void
    {
        // 调用子类的 setUp 钩子
        $this->onSetUp();
    }

    final protected function tearDown(): void
    {
        // 先让子类清理
        $this->onTearDown();

        // 清理数据库连接（只在内核启动后）
        if (self::$booted) {
            // 清理服务定位器缓存
            self::clearServiceLocatorCache();
        }

        // 执行标准清理
        $this->tearDownWebTest();
        parent::tearDown();
    }

    /**
     * 这个场景，必须使用 RunTestsInSeparateProcesses 注解的，要不会存在数据隔离的问题
     */
    #[Test]
    final public function testShouldHaveRunTestsInSeparateProcesses(): void
    {
        $reflection = new \ReflectionClass(get_class($this));
        $this->assertNotEmpty($reflection->getAttributes(RunTestsInSeparateProcesses::class), get_class($this) . ' 这个测试用例，应使用 RunTestsInSeparateProcesses 注解');
    }

    /**
     * 控制器不要给其他人继承，问题太多了
     */
    #[Test]
    final public function testControllerClassShouldBeFinal(): void
    {
        $coverClass = TestCaseHelper::extractCoverClass(new \ReflectionClass(get_class($this)));
        $this->assertNotNull($coverClass, '测试用例必须声明一个 CoversClass');
        /** @var class-string $coverClass */
        $reflection = new \ReflectionClass($coverClass);
        $this->assertTrue($reflection->isFinal(), $coverClass . ' 必须为 final，以避免不必要的继承问题');
    }

    /**
     * @param \ReflectionClass<object> $reflection
     */
    private function shouldIgnoreInvokeCheck(\ReflectionClass $reflection): bool
    {
        return $reflection->isSubclassOf(AbstractCrudController::class) || $reflection->isSubclassOf(AbstractDashboardController::class);
    }

    /**
     * 正常的控制器，都是通过 __invoke 来执行的
     */
    #[Test]
    public function testControllerShouldHaveInvokeMethod(): void
    {
        $coverClass = TestCaseHelper::extractCoverClass(new \ReflectionClass(get_class($this)));
        $this->assertNotNull($coverClass, '测试用例必须声明一个 CoversClass');
        /** @var class-string $coverClass */
        $reflection = new \ReflectionClass($coverClass);
        if ($this->shouldIgnoreInvokeCheck($reflection)) {
            return;
        }

        $this->assertTrue($reflection->hasMethod('__invoke'), "控制器类 {$coverClass} 必须使用 __invoke 来实现逻辑");
    }

    /**
     * 控制器类上不允许定义路由
     */
    #[Test]
    final public function testControllerClassShouldNotHaveRouteAttribute(): void
    {
        $reflection = new \ReflectionClass(get_class($this));
        $coverClass = TestCaseHelper::extractCoverClass($reflection);
        $this->assertNotNull($coverClass, '测试用例必须声明一个 CoversClass');

        if (count($reflection->getAttributes(CoversClass::class)) > 1) {
            // 大于一个，说明可能是复合的验收测试
            return;
        }

        /** @var class-string $coverClass */
        $reflection = new \ReflectionClass($coverClass);
        if ($this->shouldIgnoreInvokeCheck($reflection)) {
            return;
        }

        $this->assertCount(
            0,
            $reflection->getAttributes(Route::class),
            "不允许在 {$coverClass} 类上使用路由注解"
        );
    }

    /**
     * 必须在 __invoke 函数中使用路由注解
     */
    #[Test]
    final public function testInvokeFunctionHasRouteAttribute(): void
    {
        $reflection = new \ReflectionClass(get_class($this));
        $coverClass = TestCaseHelper::extractCoverClass($reflection);
        $this->assertNotNull($coverClass, '测试用例必须声明一个 CoversClass');

        if (count($reflection->getAttributes(CoversClass::class)) > 1) {
            // 大于一个，说明可能是复合的验收测试
            return;
        }

        /** @var class-string $coverClass */
        $reflection = new \ReflectionClass($coverClass);
        if ($this->shouldIgnoreInvokeCheck($reflection)) {
            return;
        }

        $this->assertGreaterThanOrEqual(
            1,
            $reflection->getMethod('__invoke')->getAttributes(Route::class),
            "必须在 {$coverClass}::__invoke 上使用 Route 注解来声明路由。use " . Route::class . ';',
        );
    }

    /**
     * @return array<string>
     */
    final public static function provideFullMethods(): array
    {
        // TODO 这里很奇怪， HEAD 请求貌似 Symfony 内部会当作 GET 来处理，看着像是一个非标准的行为
        return [
            'GET',
            'POST',
            'PUT',
            'DELETE',
            'TRACE',
            'PURGE',
        ];
    }

    #[Test]
    public function testEnsureTestMethodNotAllowed(): void
    {
        $reflection = new \ReflectionClass(get_class($this));

        $attributes = $reflection->getMethod('testMethodNotAllowed')->getAttributes(DataProvider::class);
        $this->assertCount(1, $attributes, get_class($this) . '::testMethodNotAllowed必须使用DataProvider注解声明测试数据，并使用 provideNotAllowedMethods 这个DataProvider');

        foreach ($attributes as $attribute) {
            $attribute = $attribute->newInstance();
            $this->assertInstanceOf(DataProvider::class, $attribute);
            $this->assertEquals('provideNotAllowedMethods', $attribute->methodName(), get_class($this) . '::testMethodNotAllowed的DataProvider注解，参数必须是provideNotAllowedMethods');
        }
    }

    /**
     * 测试不支持的方法
     *
     * 子类必须实现此方法以测试不支持的 HTTP 方法，
     * 通常应该期望抛出 MethodNotAllowedHttpException 异常。
     *
     * @phpstan-ignore-next-line
     */
    #[Test]
    #[DataProvider('provideNotAllowedMethods')]
    abstract public function testMethodNotAllowed(string $method): void;

    /**
     * 提供无法访问的控制器路由
     *
     * @return iterable<string, array{string}>
     */
    final public static function provideNotAllowedMethods(): iterable
    {
        $coverClass = TestCaseHelper::extractCoverClass(new \ReflectionClass(get_called_class()));
        self::assertNotNull($coverClass, '测试用例必须声明一个 CoversClass');
        /** @var class-string $coverClass */
        $reflection = new \ReflectionClass($coverClass);

        if (!$reflection->hasMethod('__invoke')) {
            yield 'INVALID method' => ['INVALID'];

            return;
        }

        $has = false;
        foreach ($reflection->getMethod('__invoke')->getAttributes(Route::class) as $attribute) {
            $route = $attribute->newInstance();
            /** @var Route $route */
            $allowMethods = $route->getMethods();
            if ([] === $allowMethods) {
                $allowMethods = self::provideFullMethods();
            }

            $notAllowedMethods = array_diff(self::provideFullMethods(), $allowMethods);
            foreach ($notAllowedMethods as $method) {
                yield "{$method} method" => [$method];
                $has = true;
            }

            break;
            // 有一些路由会同时定义多个，这种情况也算是符合预期的，但是我们就没必要处理那么多了
        }

        if (!$has) {
            yield 'INVALID method' => ['INVALID'];
        }
    }
}
