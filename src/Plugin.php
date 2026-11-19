<?php
/**
 * Plugin bootstrap.
 *
 * @package Saizul\LoginLimit
 */

namespace Saizul\LoginLimit;

use Saizul\LoginLimit\Admin\SettingsPage;
use Saizul\LoginLimit\Cli\Command;
use Saizul\LoginLimit\Store\AttemptStore;
use Saizul\LoginLimit\Store\DbAttemptStore;
use Saizul\LoginLimit\Store\DbLogStore;
use Saizul\LoginLimit\Store\LogStore;

defined( 'ABSPATH' ) || exit;

/**
 * Wires the authentication hooks, the settings screen, cron and WP-CLI.
 */
final class Plugin {

	const VERSION   = '0.1.0';
	const CRON_HOOK = 'wp_login_limit_purge';

	/**
	 * Running instance.
	 *
	 * @var Plugin|null
	 */
	private static $instance;

	/**
	 * Main plugin file.
	 *
	 * @var string
	 */
	private $file;

	/**
	 * Attempt storage.
	 *
	 * @var AttemptStore
	 */
	private $attempts;

	/**
	 * Lockout log.
	 *
	 * @var LogStore
	 */
	private $log;

	/**
	 * Returns the current time.
	 *
	 * @var callable|null
	 */
	private $clock;

	/**
	 * Constructor.
	 *
	 * @param string            $file     Main plugin file.
	 * @param AttemptStore|null $attempts Attempt storage (database by default).
	 * @param LogStore|null     $log      Lockout log (database by default).
	 * @param callable|null     $clock    Returns the current time (tests).
	 */
	public function __construct( string $file, ?AttemptStore $attempts = null, ?LogStore $log = null, ?callable $clock = null ) {
		$this->file     = $file;
		$this->attempts = $attempts ?? new DbAttemptStore();
		$this->log      = $log ?? new DbLogStore();
		$this->clock    = $clock;
	}

	/**
	 * Create the instance and register the hooks.
	 *
	 * @param string $file Main plugin file.
	 */
	public static function boot( string $file ): self {
		if ( null === self::$instance ) {
			self::$instance = new self( $file );
			self::$instance->hooks();
		}

		return self::$instance;
	}

	/**
	 * Running instance, if booted.
	 */
	public static function instance(): ?self {
		return self::$instance;
	}

	/**
	 * Forget the instance (tests).
	 */
	public static function reset(): void {
		self::$instance = null;
	}

	/**
	 * Register hooks.
	 */
	public function hooks(): void {
		add_action( 'init', array( $this, 'load_textdomain' ) );
		add_action( 'init', array( Schema::class, 'maybe_install' ), 1 );
		add_action( 'init', array( $this, 'schedule' ) );
		add_action( self::CRON_HOOK, array( $this, 'purge' ) );

		( new Auth( $this ) )->register();

		if ( is_admin() ) {
			( new SettingsPage( $this ) )->register();
		}
		if ( defined( 'WP_CLI' ) && WP_CLI && class_exists( '\WP_CLI' ) ) {
			\WP_CLI::add_command( 'login-limit', new Command( $this ) );
		}
	}

	/**
	 * Activation: create tables, schedule the clean-up.
	 */
	public static function activate(): void {
		Schema::install();
		if ( ! wp_next_scheduled( self::CRON_HOOK ) ) {
			wp_schedule_event( time() + HOUR_IN_SECONDS, 'daily', self::CRON_HOOK );
		}
	}

	/**
	 * Deactivation: stop the clean-up. Data stays until uninstall.
	 */
	public static function deactivate(): void {
		wp_clear_scheduled_hook( self::CRON_HOOK );
	}

	/**
	 * Make sure the daily clean-up is scheduled.
	 */
	public function schedule(): void {
		if ( ! wp_next_scheduled( self::CRON_HOOK ) ) {
			wp_schedule_event( time() + HOUR_IN_SECONDS, 'daily', self::CRON_HOOK );
		}
	}

	/**
	 * Load translations for installs outside WordPress.org.
	 */
	public function load_textdomain(): void {
		load_plugin_textdomain( 'wp-login-limit', false, dirname( plugin_basename( $this->file ) ) . '/languages' );
	}

	/**
	 * Daily clean-up of stale counters and old log entries.
	 */
	public function purge(): int {
		return $this->limiter()->purge();
	}

	/**
	 * Current settings.
	 *
	 * @return array<string,mixed>
	 */
	public function settings(): array {
		return Settings::get();
	}

	/**
	 * Limiter with the current settings.
	 */
	public function limiter(): Limiter {
		return new Limiter( $this->attempts, $this->log, $this->settings(), $this->clock );
	}

	/**
	 * Notifier with the current settings.
	 */
	public function notifier(): Notifier {
		return new Notifier( $this->settings() );
	}

	/**
	 * Attempt storage.
	 */
	public function attempts(): AttemptStore {
		return $this->attempts;
	}

	/**
	 * Lockout log.
	 */
	public function log(): LogStore {
		return $this->log;
	}

	/**
	 * Write a fail2ban line to the PHP error log when enabled.
	 *
	 * @param string $event    Event.
	 * @param string $ip       Client IP.
	 * @param string $username Username.
	 * @param string $gateway  Gateway.
	 */
	public function fail2ban( string $event, string $ip, string $username, string $gateway ): void {
		if ( empty( $this->settings()['fail2ban'] ) ) {
			return;
		}
		$line = Fail2ban::line( $event, $ip, $username, $gateway );
		if ( '' === $line ) {
			return;
		}

		/**
		 * Filters where fail2ban lines go. Return false to handle the line yourself.
		 *
		 * @param bool   $write Write it with error_log().
		 * @param string $line  The line.
		 */
		if ( apply_filters( 'login_limit_fail2ban_write', true, $line ) ) {
			error_log( $line ); // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log -- Intended: fail2ban reads the PHP error log.
		}
	}

	/**
	 * Main plugin file.
	 */
	public function file(): string {
		return $this->file;
	}

	/**
	 * Capability needed to manage the plugin.
	 */
	public static function capability(): string {
		/**
		 * Filters the capability needed to change settings and unlock clients.
		 *
		 * @param string $capability Capability, `manage_options` by default.
		 */
		$capability = apply_filters( 'login_limit_capability', 'manage_options' );

		return is_string( $capability ) && '' !== $capability ? $capability : 'manage_options';
	}
}
