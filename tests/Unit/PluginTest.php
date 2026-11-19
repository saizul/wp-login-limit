<?php
declare(strict_types=1);

namespace Saizul\LoginLimit\Tests\Unit;

use Saizul\LoginLimit\Plugin;
use Saizul\LoginLimit\Schema;
use Saizul\LoginLimit\Tests\WpTestCase;
use WpStubs;

/**
 * Bootstrap, cron, schema and uninstall.
 */
final class PluginTest extends WpTestCase {

	public function test_hooks(): void {
		$this->plugin->hooks();

		self::assertSame( 99, has_filter( 'authenticate' ) );
		self::assertSame( 1, has_filter( 'init', array( Schema::class, 'maybe_install' ) ) );
		self::assertSame( 10, has_filter( Plugin::CRON_HOOK, array( $this->plugin, 'purge' ) ) );
		self::assertFalse( has_filter( 'admin_menu' ) );

		WpStubs::reset();
		WpStubs::$admin = true;
		$this->plugin->hooks();
		self::assertNotFalse( has_filter( 'admin_menu' ) );
	}

	public function test_boot_returns_one_instance(): void {
		$first = Plugin::boot( '/x/wp-login-limit.php' );

		self::assertSame( $first, Plugin::boot( '/y/wp-login-limit.php' ) );
		self::assertSame( $first, Plugin::instance() );
	}

	public function test_activation_and_deactivation(): void {
		Plugin::activate();

		self::assertCount( 2, WpStubs::$registry['dbDelta'] );
		self::assertStringContainsString( 'CREATE TABLE wp_login_limit_attempts (', WpStubs::$registry['dbDelta'][0] );
		self::assertStringContainsString( 'PRIMARY KEY  (lock_key)', WpStubs::$registry['dbDelta'][0] );
		self::assertStringContainsString( 'CREATE TABLE wp_login_limit_log (', WpStubs::$registry['dbDelta'][1] );
		self::assertSame( Schema::VERSION, WpStubs::$options[ Schema::VERSION_OPTION ] );
		self::assertNotFalse( wp_next_scheduled( Plugin::CRON_HOOK ) );

		Plugin::deactivate();
		self::assertFalse( wp_next_scheduled( Plugin::CRON_HOOK ) );
	}

	public function test_maybe_install_and_schedule(): void {
		WpStubs::$options[ Schema::VERSION_OPTION ] = Schema::VERSION;
		Schema::maybe_install();
		self::assertArrayNotHasKey( 'dbDelta', WpStubs::$registry );

		$this->plugin->schedule();
		$first = wp_next_scheduled( Plugin::CRON_HOOK );
		$this->plugin->schedule();
		self::assertSame( $first, wp_next_scheduled( Plugin::CRON_HOOK ) );
	}

	public function test_purge(): void {
		$this->plugin->limiter()->fail( '203.0.113.5', 'a', 'login' );
		$this->now += 2 * 86400;

		self::assertSame( 2, $this->plugin->purge() );
	}

	public function test_capability_filter(): void {
		self::assertSame( 'manage_options', Plugin::capability() );
		add_filter(
			'login_limit_capability',
			static function () {
				return '';
			}
		);
		self::assertSame( 'manage_options', Plugin::capability() );
	}

	public function test_uninstall(): void {
		WpStubs::$options                       = array(
			'wp_login_limit_settings'     => array(),
			'wp_login_limit_db_version'   => '1',
			'wp_login_limit_notify_state' => array(),
			'unrelated'                   => 'kept',
		);
		WpStubs::$user_meta[1]                  = array( 'wp_login_limit_known_networks' => array( '1.2.3.4' => 1 ), 'other' => 'kept' );
		WpStubs::$events[ Plugin::CRON_HOOK ] = 1;
		if ( ! defined( 'WP_UNINSTALL_PLUGIN' ) ) {
			define( 'WP_UNINSTALL_PLUGIN', 'wp-login-limit/wp-login-limit.php' );
		}
		require dirname( __DIR__, 2 ) . '/uninstall.php';

		self::assertSame( array( 'unrelated' => 'kept' ), WpStubs::$options );
		self::assertSame( array( 'other' => 'kept' ), WpStubs::$user_meta[1] );
		self::assertSame( array( 'DROP TABLE IF EXISTS `wp_login_limit_attempts`', 'DROP TABLE IF EXISTS `wp_login_limit_log`' ), $GLOBALS['wpdb']->queries );
		self::assertArrayNotHasKey( Plugin::CRON_HOOK, WpStubs::$events );
	}
}
