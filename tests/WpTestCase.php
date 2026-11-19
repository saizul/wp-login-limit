<?php
declare(strict_types=1);

namespace Saizul\LoginLimit\Tests;

use PHPUnit\Framework\TestCase;
use Saizul\LoginLimit\Plugin;
use Saizul\LoginLimit\Settings;
use Saizul\LoginLimit\Tests\Support\MemoryAttemptStore;
use Saizul\LoginLimit\Tests\Support\MemoryLogStore;
use WP_CLI;
use WpStubs;

/**
 * Base class: resets the WordPress and WP-CLI stubs before every test and
 * offers a plugin wired to in-memory stores and a fake clock.
 */
abstract class WpTestCase extends TestCase {

	const NOW = 1800000000;

	/** @var MemoryAttemptStore */
	protected $attempts;

	/** @var MemoryLogStore */
	protected $log;

	/** @var Plugin */
	protected $plugin;

	/** @var int */
	protected $now = self::NOW;

	/** @var string[] */
	protected $fail2ban = array();

	protected function setUp(): void {
		WpStubs::reset();
		WP_CLI::reset();
		Plugin::reset();
		$_GET     = array();
		$_POST    = array();
		$_REQUEST = array();
		add_filter( 'login_limit_exit', '__return_false' );
		add_filter(
			'login_limit_fail2ban_write',
			function ( $write, $line ) {
				$this->fail2ban[] = $line;
				return false;
			},
			10,
			2
		);
		WpStubs::$options['admin_email'] = 'owner@example.org';
		WpStubs::$options['blogname']    = 'Example &amp; Co';

		$this->now      = self::NOW;
		$this->fail2ban = array();
		$this->attempts = new MemoryAttemptStore();
		$this->log      = new MemoryLogStore();
		$this->plugin   = new Plugin(
			'/var/www/wp-content/plugins/wp-login-limit/wp-login-limit.php',
			$this->attempts,
			$this->log,
			function () {
				return $this->now;
			}
		);
	}

	/**
	 * Store settings.
	 *
	 * @param array<string,mixed> $overrides Overrides.
	 */
	protected static function settings( array $overrides ): void {
		WpStubs::$options[ Settings::OPTION ] = array_merge( Settings::defaults(), $overrides );
	}

	/**
	 * Add a user to the stubs.
	 */
	protected static function user( int $id, string $login, string $email ): object {
		$user                     = new \stdClass();
		$user->ID                 = $id;
		$user->user_login         = $login;
		$user->user_email         = $email;
		WpStubs::$users[ $login ] = $user;
		return $user;
	}
}
