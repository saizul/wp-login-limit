<?php
declare(strict_types=1);

namespace Saizul\LoginLimit\Tests\Unit;

use Saizul\LoginLimit\Auth;
use Saizul\LoginLimit\Settings;
use Saizul\LoginLimit\Tests\WpTestCase;
use WP_Error;
use WpStubs;

/**
 * wp-login.php, XML-RPC and application password hooks.
 */
final class AuthTest extends WpTestCase {

	/** @var Auth */
	private $auth;

	protected function setUp(): void {
		parent::setUp();
		$this->auth = new Auth( $this->plugin );
		$_SERVER['REMOTE_ADDR'] = '203.0.113.5';
	}

	/**
	 * One wp_signon() attempt the way core runs it: authenticate filter, then
	 * wp_login_failed on error.
	 *
	 * @param mixed $core_result What core's own callbacks returned.
	 * @return mixed
	 */
	private function attempt( string $username, $core_result = null, string $password = 'secret' ) {
		$core_result = $core_result ?? new WP_Error( 'incorrect_password', 'The password you entered for the username is incorrect.' );
		$result      = $this->auth->authenticate( $core_result, $username, $password );
		if ( $result instanceof WP_Error ) {
			$this->auth->login_failed( $username, $result );
		}
		return $result;
	}

	private static function wp_user( string $login = 'admin' ): object {
		return self::user( 1, $login, $login . '@example.org' );
	}

	public function test_register(): void {
		$this->auth->register();

		self::assertSame( 99, has_filter( 'authenticate', array( $this->auth, 'authenticate' ) ) );
		self::assertSame( 21, has_filter( 'determine_current_user', array( $this->auth, 'check_application_password' ) ) );
		self::assertSame( 10, has_filter( 'application_password_failed_authentication', array( $this->auth, 'application_password_failed' ) ) );
		self::assertFalse( has_filter( 'xmlrpc_enabled' ) );
	}

	public function test_xmlrpc_can_be_disabled(): void {
		self::settings( array( 'xmlrpc' => Settings::XMLRPC_DISABLE ) );
		$this->auth->register();

		self::assertFalse( apply_filters( 'xmlrpc_enabled', true ) );
	}

	public function test_empty_form_is_not_an_attempt(): void {
		$result = $this->auth->authenticate( null, '', '' );

		self::assertNull( $result );
		self::assertSame( array(), $this->attempts->rows );
	}

	public function test_generic_error_message(): void {
		foreach ( array( 'invalid_username', 'invalid_email', 'incorrect_password' ) as $code ) {
			$result = $this->auth->authenticate( new WP_Error( $code, 'Revealing' ), 'someone', 'x' );
			self::assertSame( 'login_limit_invalid', $result->get_error_code() );
			self::assertStringContainsString( 'The username or password is incorrect.', $result->get_error_message() );
		}

		$empty = new WP_Error( 'empty_password', 'The password field is empty.' );
		self::assertSame( $empty, $this->auth->authenticate( $empty, 'someone', '' ) );

		self::settings( array( 'generic_errors' => false ) );
		self::assertSame( 'invalid_username', $this->auth->authenticate( new WP_Error( 'invalid_username', 'x' ), 'someone', 'x' )->get_error_code() );
	}

	public function test_successful_login_passes_through(): void {
		$user = self::wp_user();

		self::assertSame( $user, $this->auth->authenticate( $user, 'admin', 'right' ) );
	}

	public function test_lockout_after_five_failures_even_with_the_right_password(): void {
		for ( $i = 0; $i < 5; $i++ ) {
			$this->attempt( 'admin' );
		}
		$result = $this->auth->authenticate( self::wp_user(), 'admin', 'right' );

		self::assertInstanceOf( WP_Error::class, $result );
		self::assertSame( 'login_limit_locked', $result->get_error_code() );
		self::assertStringContainsString( 'Please try again in 15 mins.', $result->get_error_message() );
	}

	public function test_refused_attempts_are_not_counted_again(): void {
		for ( $i = 0; $i < 5; $i++ ) {
			$this->attempt( 'admin' );
		}
		for ( $i = 0; $i < 10; $i++ ) {
			$this->attempt( 'admin' );
		}

		self::assertSame( 1, $this->attempts->rows['ip:203.0.113.5']['lockouts'] );
		self::assertSame( 5, $this->attempts->rows['user:admin']['failures'] );
	}

	public function test_email_counts_as_the_users_login(): void {
		self::user( 7, 'Jane', 'jane@example.org' );
		$this->attempt( 'JANE@example.org' );
		$this->attempt( 'jane' );

		self::assertSame( 2, $this->attempts->rows['user:jane']['failures'] );
		self::assertArrayNotHasKey( 'user:jane@example.org', $this->attempts->rows );
	}

	public function test_success_resets_and_remembers_the_network(): void {
		$user = self::wp_user();
		$this->attempt( 'admin' );
		$this->auth->login_succeeded( 'admin', $user );

		self::assertSame( 0, $this->attempts->rows['ip:203.0.113.5']['failures'] );
		self::assertSame( array( '203.0.113.5' => self::NOW ), WpStubs::$user_meta[1][ Auth::KNOWN_META ] );
	}

	public function test_known_network_survives_a_username_lockout(): void {
		self::settings( array( 'ip_max_retries' => 100, 'user_max_retries' => 3 ) );
		$user = self::wp_user();
		$this->auth->login_succeeded( 'admin', $user );

		$_SERVER['REMOTE_ADDR'] = '198.51.100.66';
		for ( $i = 0; $i < 3; $i++ ) {
			$this->attempt( 'admin' );
		}
		self::assertSame( 'login_limit_locked', $this->auth->authenticate( $user, 'admin', 'right' )->get_error_code() );

		$_SERVER['REMOTE_ADDR'] = '203.0.113.5';
		self::assertSame( $user, $this->auth->authenticate( $user, 'admin', 'right' ) );
	}

	public function test_known_networks_are_capped(): void {
		$user = self::wp_user();
		for ( $i = 1; $i <= 15; $i++ ) {
			$_SERVER['REMOTE_ADDR'] = '198.51.100.' . $i;
			$this->now++;
			$this->auth->login_succeeded( 'admin', $user );
		}

		$known = WpStubs::$user_meta[1][ Auth::KNOWN_META ];
		self::assertCount( Auth::KNOWN_MAX, $known );
		self::assertArrayHasKey( '198.51.100.15', $known );
		self::assertArrayNotHasKey( '198.51.100.1', $known );
	}

	public function test_denylisted_ip_is_refused_and_logged(): void {
		self::settings( array( 'denylist' => array( '203.0.113.0/24' ) ) );
		$result = $this->attempt( 'admin', self::wp_user() );

		self::assertSame( 'login_limit_denied', $result->get_error_code() );
		self::assertSame( array( 'denied' ), $this->log->events() );
		self::assertSame( array(), $this->attempts->rows );
	}

	public function test_client_ip_behind_a_trusted_proxy(): void {
		self::settings( array( 'trusted_proxies' => array( '10.0.0.0/8' ) ) );
		$_SERVER['REMOTE_ADDR']          = '10.0.0.2';
		$_SERVER['HTTP_X_FORWARDED_FOR'] = '1.1.1.1, 198.51.100.20';
		$this->attempt( 'admin' );

		self::assertArrayHasKey( 'ip:198.51.100.20', $this->attempts->rows );
		self::assertSame( '198.51.100.20', $this->auth->client_ip() );
	}

	public function test_client_ip_filter(): void {
		add_filter(
			'login_limit_client_ip',
			static function () {
				return '192.0.2.77';
			}
		);
		self::assertSame( '192.0.2.77', $this->auth->client_ip() );

		add_filter(
			'login_limit_client_ip',
			static function () {
				return 'garbage';
			}
		);
		self::assertSame( '', $this->auth->client_ip() );
	}

	public function test_fail2ban_lines(): void {
		self::settings( array( 'fail2ban' => true ) );
		for ( $i = 0; $i < 6; $i++ ) {
			$this->attempt( "evil\"\nuser" );
		}

		self::assertSame( 'wp-login-limit: authentication failure from 203.0.113.5 user="evil?user" gateway=login', $this->fail2ban[0] );
		self::assertSame( 'wp-login-limit: lockout from 203.0.113.5 user="evil?user" gateway=login', $this->fail2ban[5] );
		self::assertSame( 'wp-login-limit: blocked from 203.0.113.5 user="evil?user" gateway=login', $this->fail2ban[6] );
		self::assertCount( 7, $this->fail2ban );
	}

	public function test_fail2ban_is_off_by_default(): void {
		$this->attempt( 'admin' );

		self::assertSame( array(), $this->fail2ban );
	}

	public function test_lockout_action_and_notification(): void {
		self::settings( array( 'notify' => Settings::NOTIFY_ALL ) );
		$fired = array();
		add_action(
			'login_limit_lockout',
			static function ( $lockout ) use ( &$fired ) {
				$fired[] = $lockout->reason;
			}
		);
		for ( $i = 0; $i < 5; $i++ ) {
			$this->attempt( 'admin' );
		}

		self::assertSame( array( 'ip' ), $fired );
		self::assertCount( 1, WpStubs::$mail );
		self::assertSame( 'owner@example.org', WpStubs::$mail[0]['to'] );
	}

	public function test_application_password_failures_are_counted(): void {
		$_SERVER['PHP_AUTH_USER'] = 'admin';
		for ( $i = 0; $i < 5; $i++ ) {
			$this->auth->application_password_failed( new WP_Error( 'incorrect_password', 'x' ) );
		}

		self::assertSame( 1, $this->attempts->rows['ip:203.0.113.5']['lockouts'] );
		self::assertSame( 'rest', $this->log->entries[0]['gateway'] );
	}

	public function test_application_password_failures_inside_authenticate_are_left_to_wp_login_failed(): void {
		$_SERVER['PHP_AUTH_USER'] = 'admin';
		WpStubs::$doing           = array( 'authenticate' );
		$this->auth->application_password_failed( new WP_Error( 'incorrect_password', 'x' ) );
		WpStubs::$doing = array();
		$this->auth->application_password_failed( new WP_Error( 'application_passwords_disabled', 'x' ) );
		$this->auth->application_password_failed( 'not an error' );

		self::assertSame( array(), $this->attempts->rows );
	}

	public function test_locked_client_cannot_use_an_application_password(): void {
		global $wp_rest_application_password_status;
		$_SERVER['PHP_AUTH_USER'] = 'admin';
		for ( $i = 0; $i < 5; $i++ ) {
			$this->auth->application_password_failed( new WP_Error( 'incorrect_password', 'x' ) );
		}

		$wp_rest_application_password_status = true;
		self::assertFalse( $this->auth->check_application_password( 1 ) );
		self::assertInstanceOf( WP_Error::class, $wp_rest_application_password_status );
		self::assertSame( 'login_limit_locked', $wp_rest_application_password_status->get_error_code() );
		self::assertSame( array( 'status' => 429 ), $wp_rest_application_password_status->get_error_data() );
	}

	public function test_application_password_check_is_skipped_when_not_used(): void {
		global $wp_rest_application_password_status;
		self::settings( array( 'denylist' => array( '203.0.113.5' ) ) );

		$wp_rest_application_password_status = null;
		self::assertSame( 1, $this->auth->check_application_password( 1 ) );

		$wp_rest_application_password_status = true;
		self::assertSame( 1, $this->auth->check_application_password( 1 ) );

		$_SERVER['PHP_AUTH_USER'] = 'admin';
		self::assertFalse( $this->auth->check_application_password( 1 ) );
		self::assertSame( array( 'status' => 403 ), $wp_rest_application_password_status->get_error_data() );
	}

	public function test_application_password_success_resets(): void {
		$_SERVER['PHP_AUTH_USER'] = 'admin';
		$this->auth->application_password_failed( new WP_Error( 'incorrect_password', 'x' ) );
		$this->auth->application_password_succeeded( self::wp_user() );
		$this->auth->application_password_succeeded( null );

		self::assertSame( 0, $this->attempts->rows['ip:203.0.113.5']['failures'] );
	}

	public function test_shake_codes_and_gateway(): void {
		self::assertSame( array( 'x', 'login_limit_locked', 'login_limit_denied', 'login_limit_invalid' ), $this->auth->shake_error_codes( array( 'x' ) ) );
		self::assertContains( 'login_limit_locked', $this->auth->shake_error_codes( null ) );
		self::assertSame( 'login', Auth::gateway() );
	}
}
