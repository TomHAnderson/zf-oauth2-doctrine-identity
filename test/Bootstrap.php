<?php
/**
 * @copyright Copyright (c) 2014 Zend Technologies USA Inc. (http://www.zend.com)
 * @license   http://opensource.org/licenses/BSD-3-Clause BSD-3-Clause
 */

namespace ZFTest\OAuth2\Doctrine\Identity;

use Zend\Loader\AutoloaderFactory;
use RuntimeException;

error_reporting(E_ALL | E_STRICT);
chdir(__DIR__);
date_default_timezone_set('utc');

/**
 * Test bootstrap, for setting up autoloading
 *
 * @subpackage UnitTest
 */
class Bootstrap
{
    protected static $serviceManager;

    public static function init()
    {
        $config = __DIR__ . '/asset/autoload/oauth2.doctrine-orm.global.php';
        copy(
            __DIR__ . '/../vendor/api-skeletons/zf-oauth2-doctrine/config/oauth2.doctrine-orm.global.php.dist',
            $config
        );
        `find $config -type f -exec sed -i '' -e 's/ZFTest\\\\OAuth2\\\\Doctrine\\\\Entity\\\\User/ZFTest\\\\OAuth2\\\\Doctrine\\\\Identity\\\\Entity\\\\User/g' {} \;`;

        static::initAutoloader();
    }

    protected static function initAutoloader()
    {
        $vendorPath = static::findParentPath('vendor');

        if (is_readable($vendorPath . '/autoload.php')) {
            $loader = include $vendorPath . '/autoload.php';
            return;
        }

        $zf2Path = getenv('ZF2_PATH') ?: (defined('ZF2_PATH') ? ZF2_PATH : (is_dir($vendorPath . '/ZF2/library') ? $vendorPath . '/ZF2/library' : false));

        if (!$zf2Path) {
            throw new RuntimeException('Unable to load ZF2. Run `php composer.phar install` or define a ZF2_PATH environment variable.');
        }

        if (isset($loader)) {
            $loader->add('Zend', $zf2Path . '/Zend');
        } else {
            include $zf2Path . '/Zend/Loader/AutoloaderFactory.php';
            AutoloaderFactory::factory(array(
                'Zend\Loader\StandardAutoloader' => array(
                    'autoregister_zf' => true,
                    'namespaces' => array(
                        'ZF\OAuth2\Doctrine\Identity' => __DIR__ . '/../src/',
                        __NAMESPACE__ => __DIR__,
                    ),
                ),
            ));
        }
    }

    protected static function findParentPath($path)
    {
        $dir = __DIR__;
        $previousDir = '.';
        while (!is_dir($dir . '/' . $path)) {
            $dir = dirname($dir);
            if ($previousDir === $dir) return false;
            $previousDir = $dir;
        }
        return $dir . '/' . $path;
    }
}

Bootstrap::init();
