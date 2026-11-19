<?php
declare(strict_types=1);

namespace Saizul\LoginLimit\Tests\Unit;

use Saizul\LoginLimit\Admin\SettingsPage;
use Saizul\LoginLimit\Settings;
use Saizul\LoginLimit\Tests\WpTestCase;
use WpDie;
use WpStubs;

/**
 * Settings > Login Limit.
 */
final class AdminTest extends WpTestCase {

	/** @var SettingsPage */
	private $page;

	protected function setUp(): void {
		parent::setUp();
		$this->page = new SettingsPage( $this->plugin );
	}

	private function render( array $get = array() ): string {
		$_GET = $get;
		ob_start();
		try {
			$this->page->render();
		} finally {
			$html = (string) ob_get_clean();
		}
		return $html;
	}

	private function lock( string $ip, string $user ): void {
		for ( $i = 0; $i < 5; $i++ ) {
			$this->plugin->limiter()->fail( $ip, $user, 'login' );
		}
	}

	public function test_register(): void {
		$this->page->register();
		$this->page->add_page();
		$this->page->register_settings();

		self::assertSame( array( 'wp-login-limit' ), WpStubs::calls( 'options_page' ) );
		self::assertSame( array( Settings::class, 'sanitize' ), WpStubs::$registry['settings'][ Settings::OPTION ]['sanitize_callback'] );
		self::assertFalse( WpStubs::$registry['settings'][ Settings::OPTION ]['show_in_rest'] );
		self::assertSame( 10, has_filter( 'admin_post_login_limit_unlock', array( $this->page, 'handle_unlock' ) ) );
		self::assertStringContainsString( 'options-general.php?page=wp-login-limit', $this->page->action_links( array() )[0] );
	}

	public function test_render_requires_the_capability(): void {
		WpStubs::$can = false;
		$this->expectException( WpDie::class );
		$this->render();
	}

	public function test_render_shows_ip_lockouts_settings_and_log(): void {
		$this->lock( '198.51.100.9', '<script>alert(1)</script>' );
		$html = $this->render();

		self::assertStringContainsString( 'Your IP address as this plugin sees it: 198.51.100.10', $html );
		self::assertStringContainsString( '<code>198.51.100.9</code>', $html );
		self::assertStringContainsString( 'action=login_limit_unlock', $html );
		self::assertStringContainsString( '_wpnonce=' . wp_create_nonce( 'login_limit_unlock_ip:198.51.100.9' ), $html );
		self::assertStringContainsString( 'name="wp_login_limit_settings[ip_max_retries]"', $html );
		self::assertStringContainsString( 'value="wp_login_limit"', $html );
		self::assertStringContainsString( 'IP locked out', $html );
		self::assertStringNotContainsString( '<script>alert(1)</script>', $html );
		self::assertStringContainsString( '&lt;script&gt;', $html );
	}

	public function test_proxy_hint(): void {
		$_SERVER['HTTP_X_FORWARDED_FOR'] = '203.0.113.5';
		self::assertStringContainsString( 'seems to be behind a proxy', $this->render() );

		self::settings( array( 'trusted_proxies' => array( '198.51.100.10' ) ) );
		$html = $this->render();
		self::assertStringNotContainsString( 'seems to be behind a proxy', $html );
		self::assertStringContainsString( 'sees it: 203.0.113.5 (connection from 198.51.100.10)', $html );
	}

	public function test_allowlisted_admin_is_told(): void {
		self::settings( array( 'allowlist' => array( '198.51.100.0/24' ) ) );

		self::assertStringContainsString( 'It is on the allowlist.', $this->render() );
	}

	public function test_unlock_one(): void {
		$this->lock( '198.51.100.9', 'bob' );
		$_GET = array( 'key' => 'ip:198.51.100.9' );
		$this->page->handle_unlock();

		self::assertSame( array( 'login_limit_unlock_ip:198.51.100.9' ), WpStubs::calls( 'check_admin_referer' ) );
		self::assertArrayNotHasKey( 'ip:198.51.100.9', $this->attempts->rows );
		self::assertStringContainsString( 'notice=unlocked', WpStubs::$redirect );

		$this->page->handle_unlock();
		self::assertStringContainsString( 'notice=not_found', WpStubs::$redirect );
	}

	public function test_unlock_checks_nonce_and_capability(): void {
		$this->lock( '198.51.100.9', 'bob' );
		$_GET              = array( 'key' => 'ip:198.51.100.9' );
		WpStubs::$nonce_ok = false;
		try {
			$this->page->handle_unlock();
			self::fail( 'Expected wp_die' );
		} catch ( WpDie $e ) {
			self::assertArrayHasKey( 'ip:198.51.100.9', $this->attempts->rows );
		}
		WpStubs::$nonce_ok = true;
		WpStubs::$can      = false;
		$this->expectException( WpDie::class );
		$this->page->handle_unlock_all();
	}

	public function test_unlock_all_and_clear_log(): void {
		$this->lock( '198.51.100.9', 'bob' );
		$this->page->handle_unlock_all();
		self::assertSame( array(), $this->attempts->rows );
		self::assertStringContainsString( 'notice=unlocked_all', WpStubs::$redirect );

		$this->page->handle_clear_log();
		self::assertSame( array(), $this->log->entries );
		self::assertSame( array( 'login_limit_unlock_all', 'login_limit_clear_log' ), WpStubs::calls( 'check_admin_referer' ) );
		self::assertStringContainsString( 'The lockout log is empty.', $this->render( array( 'notice' => 'log_cleared' ) ) );
	}

	public function test_empty_state(): void {
		$html = $this->render();

		self::assertStringContainsString( 'Nobody is locked out.', $html );
		self::assertStringContainsString( 'No lockouts yet.', $html );
	}
}
