<?php
/**
 * WordPress authentication hooks.
 *
 * @package Saizul\LoginLimit
 */

namespace Saizul\LoginLimit;

defined( 'ABSPATH' ) || exit;

/**
 * Connects the limiter to the three ways of logging in:
 *
 * - wp-login.php and anything else that calls wp_signon()/wp_authenticate()
 *   (`authenticate` filter at priority 99, `wp_login_failed`, `wp_login`);
 * - XML-RPC, which goes through wp_authenticate() as well (and can be
 *   switched off for authenticated methods with `xmlrpc_enabled`);
 * - REST API application passwords, checked in `determine_current_user`
 *   (priority 21, right after core's check at 20) with
 *   `application_password_failed_authentication` and
 *   `application_password_did_authenticate`.
 *
 * A locked-out request gets the same error whether the password was right
 * or wrong, so a lockout gives no password oracle.
 */
final class Auth {

	const KNOWN_META = 'wp_login_limit_known_networks';
	const KNOWN_MAX  = 10;

	/**
	 * Error codes that reveal whether a username exists.
	 */
	const REVEALING_CODES = array( 'invalid_username', 'invalid_email', 'incorrect_password', 'invalidcombo' );

	/**
	 * Plugin.
	 *
	 * @var Plugin
	 */
	private $plugin;

	/**
	 * Whether this request's attempt was refused by us (not counted again).
	 *
	 * @var bool
	 */
	private $refused = false;

	/**
	 * Constructor.
	 *
	 * @param Plugin $plugin Plugin.
	 */
	public function __construct( Plugin $plugin ) {
		$this->plugin = $plugin;
	}

	/**
	 * Register hooks.
	 */
	public function register(): void {
		add_filter( 'authenticate', array( $this, 'authenticate' ), 99, 3 );
		add_action( 'wp_login_failed', array( $this, 'login_failed' ) );
		add_action( 'wp_login', array( $this, 'login_succeeded' ), 10, 2 );
		add_filter( 'shake_error_codes', array( $this, 'shake_error_codes' ) );
		add_filter( 'determine_current_user', array( $this, 'check_application_password' ), 21 );
		add_action( 'application_password_failed_authentication', array( $this, 'application_password_failed' ) );
		add_action( 'application_password_did_authenticate', array( $this, 'application_password_succeeded' ) );
		if ( Settings::XMLRPC_DISABLE === $this->plugin->settings()['xmlrpc'] ) {
			add_filter( 'xmlrpc_enabled', '__return_false' );
		}
	}

	/**
	 * Refuse attempts from locked or denied clients, and make the error
	 * message generic.
	 *
	 * @param mixed  $user     WP_User, WP_Error or null from earlier callbacks.
	 * @param string $username Username or email as entered.
	 * @param string $password Password as entered.
	 * @return mixed
	 */
	public function authenticate( $user, $username = '', $password = '' ) {
		$username = is_string( $username ) ? $username : '';
		$password = is_string( $password ) ? $password : '';
		if ( '' === trim( $username ) && '' === $password ) {
			return $user;
		}
		$this->refused = false;

		$ip      = $this->client_ip();
		$name    = $this->canonical_username( $username );
		$lockout = $this->plugin->limiter()->check( $ip, $name, $this->known_networks( $name ) );
		if ( null !== $lockout ) {
			$this->refused = true;
			$this->plugin->limiter()->log_denied( $lockout, self::gateway() );
			$this->plugin->fail2ban( 'blocked', $ip, $name, self::gateway() );

			/**
			 * Fires when a login attempt is refused because of a lockout or the denylist.
			 *
			 * @param Lockout $lockout Why it was refused.
			 */
			do_action( 'login_limit_refused', $lockout );

			return $this->error( $lockout );
		}

		return $this->generic( $user );
	}

	/**
	 * Count a failed login.
	 *
	 * @param string $username Username or email as entered.
	 */
	public function login_failed( $username ): void {
		if ( $this->refused ) {
			$this->refused = false;
			return;
		}
		$this->record_failure( is_string( $username ) ? $username : '', self::gateway() );
	}

	/**
	 * Successful login: reset counters and remember the network.
	 *
	 * @param string $user_login Login name.
	 * @param mixed  $user       WP_User.
	 */
	public function login_succeeded( $user_login, $user = null ): void {
		$this->record_success( is_string( $user_login ) ? $user_login : '', $user );
	}

	/**
	 * Refuse a REST/basic-auth application password login while locked out.
	 * Runs after core's check, so the result is the same for right and wrong
	 * passwords.
	 *
	 * @param int|false $user_id User ID from earlier callbacks.
	 * @return int|false
	 */
	public function check_application_password( $user_id ) {
		global $wp_rest_application_password_status;
		if ( null === $wp_rest_application_password_status || ! isset( $_SERVER['PHP_AUTH_USER'] ) ) {
			return $user_id;
		}
		$ip      = $this->client_ip();
		$name    = $this->canonical_username( sanitize_user( wp_unslash( (string) $_SERVER['PHP_AUTH_USER'] ) ) );
		$lockout = $this->plugin->limiter()->check( $ip, $name, $this->known_networks( $name ) );
		if ( null === $lockout ) {
			return $user_id;
		}
		$this->plugin->limiter()->log_denied( $lockout, 'rest' );
		$this->plugin->fail2ban( 'blocked', $ip, $name, 'rest' );
		do_action( 'login_limit_refused', $lockout );

		$error = $this->error( $lockout );
		$error->add_data( array( 'status' => Lockout::REASON_DENYLIST === $lockout->reason ? 403 : 429 ) );
		$wp_rest_application_password_status = $error; // phpcs:ignore WordPress.WP.GlobalVariablesOverride.Prohibited, WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedVariableFound -- Core reads this global to build the REST error.

		return false;
	}

	/**
	 * Count a failed application password login (REST API and other
	 * basic-auth requests). XML-RPC failures are counted by login_failed().
	 *
	 * @param mixed $error WP_Error.
	 */
	public function application_password_failed( $error ): void {
		if ( doing_filter( 'authenticate' ) || ! is_object( $error ) || ! method_exists( $error, 'get_error_code' ) ) {
			return;
		}
		if ( ! in_array( $error->get_error_code(), self::REVEALING_CODES, true ) ) {
			return;
		}
		$username = isset( $_SERVER['PHP_AUTH_USER'] ) ? sanitize_user( wp_unslash( (string) $_SERVER['PHP_AUTH_USER'] ) ) : '';
		$this->record_failure( $username, 'rest' );
	}

	/**
	 * Successful application password login.
	 *
	 * @param mixed $user WP_User.
	 */
	public function application_password_succeeded( $user ): void {
		if ( is_object( $user ) && isset( $user->user_login ) ) {
			$this->record_success( (string) $user->user_login, $user );
		}
	}

	/**
	 * Let the login form shake for our errors too.
	 *
	 * @param mixed $codes Error codes.
	 * @return string[]
	 */
	public function shake_error_codes( $codes ): array {
		$codes   = is_array( $codes ) ? $codes : array();
		$codes[] = 'login_limit_locked';
		$codes[] = 'login_limit_denied';
		$codes[] = 'login_limit_invalid';

		return $codes;
	}

	/**
	 * Client IP for this request.
	 */
	public function client_ip(): string {
		$ip = IpResolver::from_settings( $this->plugin->settings() )->resolve( $_SERVER );

		/**
		 * Filters the client IP used for counting and lockouts.
		 *
		 * @param string $ip Resolved address (empty when unknown).
		 */
		$ip = apply_filters( 'login_limit_client_ip', $ip );

		return is_string( $ip ) ? (string) Ip::normalize( $ip ) : '';
	}

	/**
	 * Login gateway of this request.
	 */
	public static function gateway(): string {
		if ( defined( 'XMLRPC_REQUEST' ) && XMLRPC_REQUEST ) {
			return 'xmlrpc';
		}
		if ( defined( 'REST_REQUEST' ) && REST_REQUEST ) {
			return 'rest';
		}

		return 'login';
	}

	/**
	 * Count a failure, write the fail2ban line and notify on a new lockout.
	 *
	 * @param string $username Username or email as entered.
	 * @param string $gateway  Gateway.
	 */
	private function record_failure( string $username, string $gateway ): void {
		$ip      = $this->client_ip();
		$name    = $this->canonical_username( $username );
		$lockout = $this->plugin->limiter()->fail( $ip, $name, $gateway );
		$this->plugin->fail2ban( 'authentication failure', $ip, $name, $gateway );
		if ( null === $lockout ) {
			return;
		}
		$this->plugin->fail2ban( 'lockout', $ip, $name, $gateway );
		$this->plugin->notifier()->lockout( $lockout, $this->plugin->limiter()->now() );

		/**
		 * Fires when a client or username was just locked out.
		 *
		 * @param Lockout $lockout Lockout.
		 */
		do_action( 'login_limit_lockout', $lockout );
	}

	/**
	 * Reset counters and remember the network for this user.
	 *
	 * @param string $user_login Login name.
	 * @param mixed  $user       WP_User or null.
	 */
	private function record_success( string $user_login, $user ): void {
		$ip = $this->client_ip();
		$this->plugin->limiter()->success( $ip, Limiter::normalize_username( $user_login ) );
		if ( '' === $ip || ! is_object( $user ) || empty( $user->ID ) ) {
			return;
		}
		$network = $this->plugin->limiter()->network( $ip );
		$known   = get_user_meta( (int) $user->ID, self::KNOWN_META, true );
		$known   = is_array( $known ) ? $known : array();
		unset( $known[ $network ] );
		$known[ $network ] = $this->plugin->limiter()->now();
		arsort( $known );
		update_user_meta( (int) $user->ID, self::KNOWN_META, array_slice( $known, 0, self::KNOWN_MAX, true ) );
	}

	/**
	 * Networks a user logged in from before.
	 *
	 * @param string $username Normalised username.
	 * @return string[]
	 */
	private function known_networks( string $username ): array {
		if ( '' === $username ) {
			return array();
		}
		$user = get_user_by( 'login', $username );
		if ( ! is_object( $user ) || empty( $user->ID ) ) {
			return array();
		}
		$known = get_user_meta( (int) $user->ID, self::KNOWN_META, true );

		return is_array( $known ) ? array_map( 'strval', array_keys( $known ) ) : array();
	}

	/**
	 * Username as counted. An email address of an existing user counts as
	 * that user's login, so attackers cannot double their attempts.
	 *
	 * @param string $username Username or email as entered.
	 */
	private function canonical_username( string $username ): string {
		$username = trim( $username );
		if ( '' !== $username && false !== strpos( $username, '@' ) && is_email( $username ) ) {
			$user = get_user_by( 'email', $username );
			if ( is_object( $user ) && ! empty( $user->user_login ) ) {
				$username = (string) $user->user_login;
			}
		}

		return Limiter::normalize_username( $username );
	}

	/**
	 * Error for a refused attempt.
	 *
	 * @param Lockout $lockout Why it was refused.
	 */
	private function error( Lockout $lockout ): \WP_Error {
		if ( Lockout::REASON_DENYLIST === $lockout->reason ) {
			return new \WP_Error( 'login_limit_denied', self::prefix() . __( 'Logging in from your network is not allowed.', 'wp-login-limit' ) );
		}
		$now = $this->plugin->limiter()->now();

		return new \WP_Error(
			'login_limit_locked',
			self::prefix() . sprintf(
				/* translators: %s: time span such as "15 mins". */
				__( 'Too many failed login attempts. Please try again in %s.', 'wp-login-limit' ),
				human_time_diff( $now, max( $now + 60, $lockout->until ) )
			)
		);
	}

	/**
	 * Replace errors that reveal whether a username exists with one message.
	 *
	 * @param mixed $user WP_User, WP_Error or null.
	 * @return mixed
	 */
	private function generic( $user ) {
		if ( empty( $this->plugin->settings()['generic_errors'] ) || ! $user instanceof \WP_Error ) {
			return $user;
		}
		if ( array() === array_intersect( (array) $user->get_error_codes(), self::REVEALING_CODES ) ) {
			return $user;
		}

		return new \WP_Error( 'login_limit_invalid', self::prefix() . __( 'The username or password is incorrect.', 'wp-login-limit' ) );
	}

	/**
	 * "Error:" prefix as used by core.
	 */
	private static function prefix(): string {
		return '<strong>' . esc_html__( 'Error:', 'wp-login-limit' ) . '</strong> ';
	}
}
