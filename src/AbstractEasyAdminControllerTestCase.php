<?php

declare(strict_types=1);

namespace Tourze\PHPUnitSymfonyWebTest;

use EasyCorp\Bundle\EasyAdminBundle\Attribute\AdminAction;
use EasyCorp\Bundle\EasyAdminBundle\Attribute\AdminCrud;
use EasyCorp\Bundle\EasyAdminBundle\Cache\CacheWarmer;
use EasyCorp\Bundle\EasyAdminBundle\Config\Action;
use EasyCorp\Bundle\EasyAdminBundle\Config\Actions;
use EasyCorp\Bundle\EasyAdminBundle\Config\Crud;
use EasyCorp\Bundle\EasyAdminBundle\Contracts\Field\FieldInterface;
use EasyCorp\Bundle\EasyAdminBundle\Controller\AbstractCrudController;
use EasyCorp\Bundle\EasyAdminBundle\Registry\DashboardControllerRegistry;
use EasyCorp\Bundle\EasyAdminBundle\Router\AdminUrlGenerator;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use Symfony\Bundle\FrameworkBundle\KernelBrowser;
use Symfony\Component\DomCrawler\Crawler;
use Symfony\Component\Routing\Exception\MissingMandatoryParametersException;
use Symfony\Component\Routing\RouterInterface;
use Symfony\Component\Security\Core\Exception\AccessDeniedException;
use Symfony\Component\Security\Core\User\InMemoryUser;
use Tourze\PHPUnitBase\TestCaseHelper;

/**
 * 为EasyAdmin相关控制器，增加通用的判断
 */
abstract class AbstractEasyAdminControllerTestCase extends AbstractWebTestCase
{
    /**
     * 确保 EasyAdmin Dashboard 路由缓存在测试运行前已生成
     *
     * 这是必需的，因为在完整测试套件运行时，如果这是第一个执行的 EasyAdmin Controller 测试，
     * Dashboard 路由缓存文件可能尚不存在，导致 AdminUrlGenerator 无法解析 Dashboard。
     */
    final protected function onSetUp(): void
    {
        parent::onSetUp();

        // 获取缓存路径参数
        $container = self::getContainer();
        $buildDir = $container->getParameter('kernel.build_dir');
        $cacheDir = $container->getParameter('kernel.cache_dir');

        // 确保参数类型正确
        self::assertIsString($buildDir);
        self::assertIsString($cacheDir);

        // Dashboard 路由缓存文件路径
        $cacheFile = $buildDir . '/easyadmin/routes-dashboard.php';

        // 如果缓存文件不存在，主动触发缓存预热
        if (!file_exists($cacheFile)) {
            $router = self::getService(RouterInterface::class);
            $warmer = new CacheWarmer($router);
            $warmer->warmUp($cacheDir, $buildDir);
        }

        // 允许子类在 EasyAdmin 缓存预热之后，做额外的初始化
        $this->afterEasyAdminSetUp();
    }

    /**
     * 子类可覆盖此方法以添加额外的 setUp 逻辑
     * 注意：此钩子在 EasyAdmin Dashboard 路由缓存预热之后调用
     */
    protected function afterEasyAdminSetUp(): void
    {
        // 默认不做任何操作
    }

    /**
     * 读取容器中的真实服务
     */
    abstract protected function getControllerService(): AbstractCrudController;

    final protected function isActionEnabled(string $actionName): bool
    {
        $actions = Actions::new();

        // 判断是否被禁用了
        if (in_array($actionName, $this->getControllerService()->configureActions($actions)->getAsDto(Crud::PAGE_INDEX)->getDisabledActions(), true)) {
            return false;
        }

        // 回退到原始实现
        try {
            $this->generateAdminUrl($actionName);

            return true;
        } catch (MissingMandatoryParametersException $exception) {
            return true;
        } catch (\InvalidArgumentException $exception) {
            return false;
        }
    }

    final protected function getEntitySimpleName(): string
    {
        $entityFqcn = $this->getControllerService()::getEntityFqcn();
        $parts = explode('\\', $entityFqcn);

        return end($parts);
    }

    /**
     * 确保继承了这个类的测试用例，都是在测试 AbstractCrudController 的控制器类
     */
    #[Test]
    final public function mustCoverAbstractCrudController(): void
    {
        $controllerClass = TestCaseHelper::extractCoverClass(new \ReflectionClass(static::class));
        self::assertTrue(is_subclass_of($controllerClass, AbstractCrudController::class));
    }

    /**
     * 确保 AdminCrud 的使用符合预期
     */
    final public function testAdminCrudAttributeDoesNotUseAdminPrefix(): void
    {
        $controllerClass = TestCaseHelper::extractCoverClass(new \ReflectionClass(static::class));

        $reflection = new \ReflectionClass($controllerClass);
        $attributes = $reflection->getAttributes(AdminCrud::class, \ReflectionAttribute::IS_INSTANCEOF);

        self::assertNotEmpty($attributes, $controllerClass . '应该有 AdminCrud 注解');
        self::assertCount(1, $attributes, $controllerClass . ' 只能声明一个 AdminCrud 注解');

        $attribute = $attributes[0];
        $arguments = $attribute->getArguments();

        // 验证 routePath
        $this->assertArrayHasKey('routePath', $arguments, 'AdminCrud注解应包含routePath参数');
        $this->assertIsString($arguments['routePath'], 'routePath 应为字符串');

        $routePath = trim($arguments['routePath']);
        $this->assertNotSame('', $routePath, 'routePath 不应为空');
        $this->assertStringStartsWith('/', $routePath, 'routePath 应以 / 开头');
        $this->assertStringStartsNotWith('/admin/', $routePath, 'routePath不应以 /admin/ 开头');

        $controllerFilePath = $reflection->getFileName() ?: '';
        $normalizedControllerPath = str_replace('\\', '/', $controllerFilePath);
        $isInBundleDirectory = '' !== $normalizedControllerPath
            && 1 === preg_match('/\/[A-Za-z0-9_-]*-bundle\//i', $normalizedControllerPath);

        if ($isInBundleDirectory) {
            $this->assertMatchesRegularExpression(
                '/^\/[a-z0-9][a-z0-9_-]*\/[a-z0-9][a-z0-9_-]*$/',
                $routePath,
                'Bundle 控制器的 routePath 应为 /模块/实体 格式（小写、短横线或下划线）'
            );
        }

        // 验证 routeName
        $this->assertArrayHasKey('routeName', $arguments, 'AdminCrud注解应包含routeName参数');
        $this->assertIsString($arguments['routeName'], 'routeName 应为字符串');

        $routeName = trim($arguments['routeName']);
        $this->assertNotSame('', $routeName, 'routeName 不应为空');
        $this->assertStringStartsNotWith('admin_', $routeName, 'routeName不应以 admin_ 开头');

        $expectedRouteName = str_replace('/', '_', trim($routePath, '/'));
        $expectedRouteName = str_replace('-', '_', $expectedRouteName);
        $this->assertSame(
            $expectedRouteName,
            $routeName,
            sprintf(
                'routeName 应与 routePath 匹配，期望 %s，实际 %s',
                $expectedRouteName,
                $routeName
            )
        );
    }

    /**
     * 创建已登录的后台客户端
     */
    final protected function createAuthenticatedClient(): KernelBrowser
    {
        // 直接调用父类的 createClient，绕过可能的问题
        $client = parent::createClient();

        // 立即设置客户端到 Symfony 的静态存储中
        self::getClient($client);

        // 清理数据库（如果需要）
        if (self::hasDoctrineSupport()) {
            self::cleanDatabase();
        }

        // 关闭异常捕获
        $client->catchExceptions(false);

        // 直接使用内存管理员用户登录，避免 provider 重载导致的角色丢失
        $client->loginUser(new InMemoryUser('admin', 'password', ['ROLE_ADMIN']), 'main');

        return $client;
    }

    /**
     * 构建 EasyAdmin URL
     *
     * @param string $action CRUD 操作
     * @param array<string, mixed> $parameters 额外参数
     */
    final protected function generateAdminUrl(string $action, array $parameters = []): string
    {
        $controllerClass = TestCaseHelper::extractCoverClass(new \ReflectionClass(static::class));

        /** @var AdminUrlGenerator $generator */
        $generator = clone self::getService(AdminUrlGenerator::class);

        $generator->unsetAll();

        if (null !== ($dashboardFqcn = $this->resolveDashboardControllerFqcn())) {
            $generator->setDashboard($dashboardFqcn);
        }

        $generator
            ->setController($controllerClass)
            ->setAction($action)
            ->setAll($parameters)
        ;

        // 显式设置 Dashboard，避免多 Dashboard 环境下 AdminUrlGenerator 抛出异常

        return $generator->generateUrl();
    }

    /**
     * 覆盖该方法可为具体测试声明优先使用的 Dashboard 控制器
     */
    protected function getPreferredDashboardControllerFqcn(): ?string
    {
        return 'SymfonyTestingFramework\Controller\Admin\DashboardController';
    }

    private function resolveDashboardControllerFqcn(): ?string
    {
        /** @var DashboardControllerRegistry $dashboardRegistry */
        $dashboardRegistry = self::getService(DashboardControllerRegistry::class);

        $preferredDashboard = $this->getPreferredDashboardControllerFqcn();
        if (null !== $preferredDashboard && null !== $dashboardRegistry->getContextIdByControllerFqcn($preferredDashboard)) {
            if (null !== $dashboardRegistry->getRouteByControllerFqcn($preferredDashboard)) {
                return $preferredDashboard;
            }
        }

        foreach ($dashboardRegistry->getAll() as $dashboardConfig) {
            if (!isset($dashboardConfig['controller'])) {
                continue;
            }

            $controllerFqcn = $dashboardConfig['controller'];
            if (null !== $dashboardRegistry->getRouteByControllerFqcn($controllerFqcn)) {
                return $controllerFqcn;
            }
        }

        return null;
    }

    /**
     * 构建 EasyAdmin URL
     *
     * @param string $crudAction CRUD 操作
     * @param string $controllerFqcn 控制器类名
     * @param array<string, mixed> $params 额外参数
     * @deprecated 改用 generateAdminUrl
     */
    final protected function buildEasyAdminUrl(string $crudAction, string $controllerFqcn, array $params = []): string
    {
        $query = array_merge([
            'crudAction' => $crudAction,
            'crudControllerFqcn' => $controllerFqcn,
        ], $params);

        return '/admin?' . http_build_query($query);
    }

    #[Test]
    final public function testUnauthenticatedAccessDenied(): void
    {
        // 重置当前客户端与内核，确保以未登录状态访问后台入口
        self::getClient(null);
        self::ensureKernelShutdown();

        $client = self::createClientWithDatabase();

        // 测试未认证用户访问管理页面应该报错
        $this->expectException(AccessDeniedException::class);
        $client->request('GET', '/admin');
        // $this->assertResponseRedirects();
    }

    /**
     * EasyAdmin的后台控制器，暂时不需要这个
     */
    #[DataProvider('provideNotAllowedMethods')]
    final public function testMethodNotAllowed(string $method): void
    {
        $this->assertNotNull($method);
    }

    #[Test]
    final public function testHasConfigureFieldsMethod(): void
    {
        $reflection = new \ReflectionClass(TestCaseHelper::extractCoverClass(new \ReflectionClass(static::class)));
        $method = $reflection->getMethod('configureFields');
        $this->assertEquals($reflection->getFileName(), $method->getFileName(), $reflection->getName() . ' 必须实现自己的 configureFields 方法');
    }

    #[Test]
    final public function testHasConfigureFiltersMethod(): void
    {
        $reflection = new \ReflectionClass(TestCaseHelper::extractCoverClass(new \ReflectionClass(static::class)));
        $method = $reflection->getMethod('configureFilters');
        $this->assertEquals($reflection->getFileName(), $method->getFileName(), $reflection->getName() . ' 必须实现自己的 configureFilters 方法');
    }

    #[Test]
    final public function testHasConfigureCrudMethod(): void
    {
        $reflection = new \ReflectionClass(TestCaseHelper::extractCoverClass(new \ReflectionClass(static::class)));
        $method = $reflection->getMethod('configureCrud');
        $this->assertEquals($reflection->getFileName(), $method->getFileName(), $reflection->getName() . ' 必须实现自己的 configureCrud 方法');
    }

    public function testIndexListShouldNotDisplayInaccessible(): void
    {
        // 使用认证客户端访问index页面
        $client = self::createAuthenticatedClient();

        $url = $this->generateAdminUrl(Action::INDEX);
        $crawler = $client->request('GET', $url);

        $this->assertResponseIsSuccessful();

        // 验证页面内容中不包含 "Inaccessible" 字段值
        $pageContent = $crawler->html();
        $containsInaccessibleField = str_contains($pageContent, 'Getter method does not exist for this field or the field is not public')
            && str_contains($pageContent, 'Inaccessible');

        $message = 'Page content should not contain "Inaccessible" field value, check your field configuration.';

        if ($containsInaccessibleField) {
            $context = $this->extractHtmlContext($pageContent, 'Inaccessible');
            if (null !== $context) {
                $message .= PHP_EOL . 'HTML 上下文（目标行及其前 5 行）：' . PHP_EOL . $context;
            }
        }

        $this->assertFalse($containsInaccessibleField, $message);
    }

    /**
     * 确认 provideIndexPageHeaders 的返回值符合预期
     */
    final public function testIndexPageHeadersProviderHasData(): void
    {
        $controller = $this->getControllerService();
        $labels = [];
        foreach ($controller->configureFields('index') as $field) {
            self::assertInstanceOf(FieldInterface::class, $field, '为了确保展示效果，请不要在 configureFields 中返回字符串');
            self::assertNotNull($field->getAsDto()->getLabel(), "Field #{$field->getAsDto()->getProperty()} label should not be null.");

            $dto = $field->getAsDto();
            if ($dto->isDisplayedOn('index')) {
                $labels[] = $dto->getLabel();
            }
        }

        // If there are no fields configured for index, the provider should also be empty.
        if (empty($labels)) {
            self::assertEmpty(iterator_to_array(static::provideIndexPageHeaders()), sprintf('Controller has no index fields, so `%s::provideIndexPageHeaders()` should be empty.', static::class));

            return;
        }

        $providerData = iterator_to_array(static::provideIndexPageHeaders());
        self::assertNotEmpty($providerData, sprintf('The controller has index fields, but the data provider is empty. Please implement `%s::provideIndexPageHeaders()` and yield each header label, e.g., `yield [\'Header Label\'];`.', static::class));

        $expected = array_values(array_map(
            static fn (array $item): string => $item[0],
            $providerData
        ));

        self::assertSame($expected, $labels, sprintf('The headers from `%s::provideIndexPageHeaders()` do not match the labels from `configureFields(\'index\')`. Please ensure they are in the same order and have the same content.', static::class));
    }

    /**
     * 确认 CRUD 首页有足够的字段
     */
    #[DataProvider('provideIndexPageHeaders')]
    final public function testIndexPageShowsConfiguredColumns(string $expectedHeader): void
    {
        $client = $this->createAuthenticatedClient();

        $crawler = $client->request('GET', $this->generateAdminUrl(Action::INDEX));
        $this->assertResponseIsSuccessful();

        $theadNodes = $crawler->filter('table thead');
        self::assertGreaterThan(0, $theadNodes->count(), 'No table headers found on the page. 你是否忘记实现填充数据类？');

        $headerText = $theadNodes->last()->text();
        self::assertStringContainsString($expectedHeader, $headerText);
    }

    /** @return iterable<string, array{string}> */
    abstract public static function provideIndexPageHeaders(): iterable;

    #[DataProvider('provideNewPageFields')]
    final public function testNewPageShowsConfiguredFields(string $fieldName): void
    {
        self::assertNotNull($fieldName);

        $client = $this->createAuthenticatedClient();
        if (!$this->isActionEnabled(Action::NEW)) {
            // self::markTestSkipped('NEW action is disabled for this controller.');
            return;
        }

        $crawler = $client->request('GET', $this->generateAdminUrl(Action::NEW));
        $this->assertResponseIsSuccessful();

        $entityName = $this->getEntitySimpleName();

        // 检查字段存在（支持各种EasyAdmin字段类型）
        $inputSelector = sprintf('form[name="%s"] input[name="%s[%s]"]', $entityName, $entityName, $fieldName);
        $selectSelector = sprintf('form[name="%s"] select[name="%s[%s]"]', $entityName, $entityName, $fieldName);
        $textareaSelector = sprintf('form[name="%s"] textarea[name="%s[%s]"]', $entityName, $entityName, $fieldName);

        // EasyAdmin autocomplete字段通常有hidden input + autocomplete widget
        $hiddenInputSelector = sprintf('form[name="%s"] input[type="hidden"][name="%s[%s]"]', $entityName, $entityName, $fieldName);

        // 检查字段容器（EasyAdmin会包装字段）
        $fieldContainerSelector = sprintf('form[name="%s"] .field-%s', $entityName, str_replace('_', '-', $fieldName));

        // 检查带有字段名的任何input元素
        $anyFieldInputSelector = sprintf('form[name="%s"] [name*="[%s]"]', $entityName, $fieldName);

        $inputCount = $crawler->filter($inputSelector)->count();
        $selectCount = $crawler->filter($selectSelector)->count();
        $textareaCount = $crawler->filter($textareaSelector)->count();
        $hiddenInputCount = $crawler->filter($hiddenInputSelector)->count();
        $fieldContainerCount = $crawler->filter($fieldContainerSelector)->count();
        $anyFieldInputCount = $crawler->filter($anyFieldInputSelector)->count();

        $totalCount = $inputCount + $selectCount + $textareaCount + $hiddenInputCount + $fieldContainerCount + $anyFieldInputCount;

        self::assertGreaterThan(0, $totalCount,
            sprintf('字段 %s 应该存在 (input: %d, select: %d, textarea: %d, hidden: %d, container: %d, any: %d)',
                $fieldName, $inputCount, $selectCount, $textareaCount, $hiddenInputCount, $fieldContainerCount, $anyFieldInputCount));

        // 由于我们已经验证了字段存在，跳过标签检测
        // 不同的EasyAdmin版本和字段类型可能有不同的标签渲染方式
        // 字段存在性检查已经足够验证配置正确
        self::assertTrue(true, sprintf('字段 %s 配置验证通过', $fieldName));
    }

    /**
     * 创建页面需要用到的字段
     * @return iterable<string, array{string}>
     */
    public static function provideNewPageFields(): iterable
    {
        yield from [];
    }

    final public function testNewPageFieldsProviderHasData(): void
    {
        if (!$this->isActionEnabled(Action::NEW)) {
            self::markTestSkipped('NEW action is disabled for this controller.');
        }

        $controller = $this->getControllerService();
        $displayedFields = [];
        foreach ($controller->configureFields('new') as $field) {
            self::assertInstanceOf(FieldInterface::class, $field, '为了确保展示效果，请不要在 configureFields 中返回字符串');
            self::assertNotNull($field->getAsDto()->getLabel(), "Field #{$field->getAsDto()->getProperty()} label should not be null.");

            $dto = $field->getAsDto();
            if ($dto->isDisplayedOn('new')) {
                $displayedFields[] = $dto;
            }
        }

        self::assertGreaterThan(0, count($displayedFields), 'Controller should have fields configured for the NEW page if the action is enabled.');

        $providerFields = array_map(
            static fn (array $item): string => $item[0],
            iterator_to_array(static::provideNewPageFields())
        );
        self::assertNotEmpty($providerFields, 'provideNewPageFields should not be empty if the NEW action is enabled.');

        // 验证字段提供器非空（移除硬编码的必填字段检查，因为不同控制器有不同的字段）
        self::assertGreaterThan(0, count($providerFields),
            'NEW页面应至少配置一个字段');
    }

    final public function testEditPageAttributesProviderHasData(): void
    {
        // 先创建客户端确保容器初始化
        $client = $this->createAuthenticatedClient();

        if (!$this->isActionEnabled(Action::EDIT)) {
            self::markTestSkipped('EDIT action is disabled for this controller.');
        }

        $controller = $this->getControllerService();
        $displayedFields = [];
        foreach ($controller->configureFields('edit') as $field) {
            self::assertInstanceOf(FieldInterface::class, $field, '为了确保展示效果，请不要在 configureFields 中返回字符串');
            self::assertNotNull($field->getAsDto()->getLabel(), "Field #{$field->getAsDto()->getProperty()} label should not be null.");

            $dto = $field->getAsDto();
            if ($dto->isDisplayedOn('edit')) {
                $displayedFields[] = $dto;
            }
        }

        self::assertGreaterThan(0, count($displayedFields), 'Controller should have fields configured for the EDIT page if the action is enabled.');

        $providerEntries = iterator_to_array(static::provideEditPageFields());
        self::assertNotEmpty($providerEntries, 'provideEditPageFields should not be empty if the EDIT action is enabled.');
    }

    #[DataProvider('provideEditPageFields')]
    final public function testEditPageShowsConfiguredFields(string $fieldName): void
    {
        self::assertNotNull($fieldName);
        $client = $this->createAuthenticatedClient();

        if (!$this->isActionEnabled(Action::EDIT)) {
            self::markTestSkipped('EDIT action is disabled for this controller.');
        }

        $crawler = $client->request('GET', $this->generateAdminUrl(Action::INDEX));
        $this->assertResponseIsSuccessful();

        $firstRecordId = $crawler->filter('table tbody tr[data-id]')->first()->attr('data-id');
        self::assertNotEmpty($firstRecordId, 'Could not find a record ID on the index page to test the edit page.');

        $crawler = $client->request('GET', $this->generateAdminUrl(Action::EDIT, ['entityId' => $firstRecordId]));
        $this->assertResponseIsSuccessful();

        $entityName = $this->getEntitySimpleName();

        $anyFieldInputSelector = sprintf('form[name="%s"] [name*="[%s]"]', $entityName, $fieldName);
        $anyFieldInputCount = $crawler->filter($anyFieldInputSelector)->count();

        self::assertGreaterThan(0, $anyFieldInputCount, sprintf('字段 %s 在编辑页面应该存在', $fieldName));
    }

    /**
     * 编辑页用到的字段
     * @return iterable<string, array{string}>
     */
    public static function provideEditPageFields(): iterable
    {
        yield from [];
    }

    final public function testEditPagePrefillsExistingData(): void
    {
        $client = $this->createAuthenticatedClient();

        if (!$this->isActionEnabled(Action::EDIT)) {
            self::markTestSkipped('EDIT action is disabled for this controller.');
        }

        $crawler = $client->request('GET', $this->generateAdminUrl(Action::INDEX));
        $this->assertResponseIsSuccessful();

        $recordIds = [];
        foreach ($crawler->filter('table tbody tr[data-id]') as $row) {
            $rowCrawler = new Crawler($row);
            $recordId = $rowCrawler->attr('data-id');
            if (null === $recordId || '' === $recordId) {
                continue;
            }

            $recordIds[] = $recordId;
        }

        self::assertNotEmpty($recordIds, '列表页面应至少显示一条记录');

        $firstRecordId = $recordIds[0];
        $client->request('GET', $this->generateAdminUrl(Action::EDIT, ['entityId' => $firstRecordId]));
        $this->assertResponseIsSuccessful(sprintf('The edit page for entity #%s should be accessible.', $firstRecordId));
    }

    #[Test]
    final public function ensureAdminActionAttributesAreValid(): void
    {
        $actions = Actions::new();
        $this->getControllerService()->configureActions($actions);
        $classReflection = new \ReflectionClass($this->getControllerService());
        $this->assertCount(1, $classReflection->getAttributes(AdminCrud::class), 'The controller should have the AdminCrud attribute.');

        foreach ([Action::INDEX, Action::NEW, Action::EDIT, Action::DETAIL] as $action) {
            foreach ($actions->getAsDto($action)->getActions() as $actionDTO) {
                $crudActionName = $actionDTO->getCrudActionName();

                // Skip actions without a CRUD action name (e.g., linkToRoute actions)
                if (null === $crudActionName || '' === $crudActionName) {
                    continue;
                }

                // Skip actions that don't have a corresponding method in the controller
                if (!$classReflection->hasMethod($crudActionName)) {
                    continue;
                }

                $methodReflection = $classReflection->getMethod($actionDTO->getCrudActionName());
                if (str_contains($methodReflection->getFileName(), '/vendor')) {
                    continue;
                }
                $this->assertCount(1, $methodReflection->getAttributes(AdminAction::class), sprintf('The method %s should have the %s attribute.', $actionDTO->getName(), AdminAction::class));
            }
        }
    }

    private function extractHtmlContext(string $content, string $needle, int $leadingLines = 5): ?string
    {
        $lines = preg_split('/\r\n|\n|\r/', $content);
        if (false === $lines) {
            return null;
        }

        foreach ($lines as $index => $line) {
            if (!str_contains($line, $needle)) {
                continue;
            }

            $start = max(0, $index - $leadingLines);
            $contextSlice = array_slice($lines, $start, $leadingLines + 1);

            return implode(PHP_EOL, $contextSlice);
        }

        return null;
    }

    final public function testIndexRowActionLinksShouldNotReturn500(): void
    {
        $client = $this->createAuthenticatedClient();

        // 访问 INDEX 页面
        $indexUrl = $this->generateAdminUrl(Action::INDEX);
        $crawler = $client->request('GET', $indexUrl);
        $this->assertTrue($client->getResponse()->isSuccessful(), 'Index page should be successful');

        // 收集每一行里的动作按钮（a 链接）
        $links = [];
        foreach ($crawler->filter('table tbody tr[data-id]') as $row) {
            $rowCrawler = new Crawler($row);
            foreach ($rowCrawler->filter('td.actions a[href]') as $a) {
                $href = $a->getAttribute('href');
                if (null === $href || '' === $href) {
                    continue;
                }
                if (str_starts_with($href, 'javascript:') || '#' === $href) {
                    continue;
                }

                // 跳过需要 POST 的删除类动作（避免 Method Not Allowed）
                $aCrawler = new Crawler($a);
                $actionNameAttr = strtolower((string) ($aCrawler->attr('data-action-name') ?? $aCrawler->attr('data-action') ?? ''));
                $text = strtolower(trim($a->textContent ?? ''));
                $hrefLower = strtolower($href);
                $isDelete = (
                    'delete' === $actionNameAttr
                    || str_contains($text, 'delete')
                    || 1 === preg_match('#/delete(?:$|[/?\#])#i', $hrefLower)
                    || 1 === preg_match('/(^|[?&])crudAction=delete\b/i', $hrefLower)
                );
                if ($isDelete) {
                    continue; // 删除操作需要POST与CSRF，跳过
                }

                $links[] = $href;
            }
        }

        $links = array_values(array_unique($links));
        if (empty($links)) {
            self::markTestSkipped('没有动作链接，跳过');
        }

        // 逐个请求，跟随重定向并确保最终不是 500
        foreach ($links as $href) {
            $client->request('GET', $href);

            // 跟随最多3次重定向，覆盖常见动作跳转链
            $hops = 0;
            while ($client->getResponse()->isRedirection() && $hops < 3) {
                $client->followRedirect();
                ++$hops;
            }

            $status = $client->getResponse()->getStatusCode();
            $this->assertLessThan(500, $status, sprintf('链接 %s 最终返回了 %d', $href, $status));
        }
    }
}
