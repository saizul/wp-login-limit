<?php
/**
 * Settings > Login Limit screen.
 *
 * @package Saizul\LoginLimit
 */

namespace Saizul\LoginLimit\Admin;

use Saizul\LoginLimit\Ip;
use Saizul\LoginLimit\IpResolver;
use Saizul\LoginLimit\Plugin;
use Saizul\LoginLimit\Record;
use Saizul\LoginLimit\Settings;

defined( 'ABSPATH' ) || exit;

/**
 * Settings (Settings API, options.php checks the nonce and capability), the
 * active lockouts with unlock buttons and the lockout log. Unlocking and
 * clearing the log post to admin-post.php with their own nonces.
 */
final class SettingsPage {

	const SLUG       = 'wp-login-limit';
	const GROUP      = 'wp_login_limit';
	const UNLOCK     = 'login_limit_unlock';
	const UNLOCK_ALL = 'login_limit_unlock_all';
	const CLEAR_LOG  = 'login_limit_clear_log';

	/**
	 * Plugin.
	 *
	 * @var Plugin
	 */
	private $plugin;

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
		add_action( 'admin_menu', array( $this, 'add_page' ) );
		add_action( 'admin_init', array( $this, 'register_settings' ) );
		add_action( 'admin_post_' . self::UNLOCK, array( $this, 'handle_unlock' ) );
		add_action( 'admin_post_' . self::UNLOCK_ALL, array( $this, 'handle_unlock_all' ) );
		add_action( 'admin_post_' . self::CLEAR_LOG, array( $this, 'handle_clear_log' ) );
		add_filter( 'option_page_capability_' . self::GROUP, array( Plugin::class, 'capability' ) );
		add_filter( 'plugin_action_links_' . plugin_basename( $this->plugin->file() ), array( $this, 'action_links' ) );
	}

	/**
	 * URL of the screen.
	 *
	 * @param array<string,string> $args Extra query arguments.
	 */
	public static function url( array $args = array() ): string {
		return add_query_arg( array_merge( array( 'page' => self::SLUG ), $args ), admin_url( 'options-general.php' ) );
	}

	/**
	 * Nonced unlock URL for one record.
	 *
	 * @param string $key Record key.
	 */
	public static function unlock_url( string $key ): string {
		return add_query_arg(
			array(
				'action'   => self::UNLOCK,
				'key'      => $key,
				'_wpnonce' => wp_create_nonce( self::UNLOCK . '_' . $key ),
			),
			admin_url( 'admin-post.php' )
		);
	}

	/**
	 * Add Settings > Login Limit.
	 */
	public function add_page(): void {
		add_options_page(
			__( 'Login Limit', 'wp-login-limit' ),
			__( 'Login Limit', 'wp-login-limit' ),
			Plugin::capability(),
			self::SLUG,
			array( $this, 'render' )
		);
	}

	/**
	 * Add a Settings link on the Plugins screen.
	 *
	 * @param mixed $links Links.
	 * @return string[]
	 */
	public function action_links( $links ): array {
		$links   = is_array( $links ) ? $links : array();
		$links[] = '<a href="' . esc_url( self::url() ) . '">' . esc_html__( 'Settings', 'wp-login-limit' ) . '</a>';

		return $links;
	}

	/**
	 * Register the option.
	 */
	public function register_settings(): void {
		register_setting(
			self::GROUP,
			Settings::OPTION,
			array(
				'type'              => 'array',
				'sanitize_callback' => array( Settings::class, 'sanitize' ),
				'show_in_rest'      => false,
				'default'           => Settings::defaults(),
			)
		);
	}

	/**
	 * Print the screen.
	 */
	public function render(): void {
		if ( ! current_user_can( Plugin::capability() ) ) {
			wp_die( esc_html__( 'Sorry, you are not allowed to manage login limits.', 'wp-login-limit' ), 403 );
		}
		echo '<div class="wrap">';
		echo '<h1>' . esc_html__( 'Login Limit', 'wp-login-limit' ) . '</h1>';
		$this->notice();
		$this->render_ip_check();
		$this->render_lockouts();
		$this->render_settings();
		$this->render_log();
		echo '</div>';
	}

	/**
	 * Show the IP the plugin sees for the current admin, with proxy hints.
	 */
	private function render_ip_check(): void {
		$settings = $this->plugin->settings();
		$remote   = isset( $_SERVER['REMOTE_ADDR'] ) ? (string) Ip::normalize( sanitize_text_field( wp_unslash( $_SERVER['REMOTE_ADDR'] ) ) ) : '';
		$client   = IpResolver::from_settings( $settings )->resolve( $_SERVER );
		$limiter  = $this->plugin->limiter();

		echo '<div class="notice notice-info inline"><p>';
		/* translators: 1: client IP, 2: REMOTE_ADDR. */
		echo esc_html( sprintf( __( 'Your IP address as this plugin sees it: %1$s (connection from %2$s).', 'wp-login-limit' ), '' === $client ? '-' : $client, '' === $remote ? '-' : $remote ) );
		if ( $limiter->is_allowlisted( $client ) ) {
			echo ' ' . esc_html__( 'It is on the allowlist.', 'wp-login-limit' );
		}
		echo '</p>';
		$has_header = isset( $_SERVER['HTTP_X_FORWARDED_FOR'] ) || isset( $_SERVER['HTTP_CF_CONNECTING_IP'] ) || isset( $_SERVER['HTTP_X_REAL_IP'] );
		if ( $client === $remote && $has_header && ! IpResolver::from_settings( $settings )->is_trusted_proxy( $remote ) ) {
			echo '<p><strong>' . esc_html__( 'This site seems to be behind a proxy or CDN, but no proxy is trusted, so every visitor may share the proxy address. Add the proxy to "Trusted proxies" (or tick Cloudflare) so lockouts hit the real client.', 'wp-login-limit' ) . '</strong></p>';
		}
		echo '</div>';
	}

	/**
	 * Active lockouts with unlock links.
	 */
	private function render_lockouts(): void {
		$now     = $this->plugin->limiter()->now();
		$records = $this->plugin->limiter()->locked();

		echo '<h2>' . esc_html__( 'Active lockouts', 'wp-login-limit' ) . '</h2>';
		if ( array() === $records ) {
			echo '<p>' . esc_html__( 'Nobody is locked out.', 'wp-login-limit' ) . '</p>';
			return;
		}
		echo '<table class="widefat striped"><thead><tr>';
		echo '<th>' . esc_html__( 'Locked', 'wp-login-limit' ) . '</th>';
		echo '<th>' . esc_html__( 'Until', 'wp-login-limit' ) . '</th>';
		echo '<th>' . esc_html__( 'Lockout number', 'wp-login-limit' ) . '</th>';
		echo '<th></th></tr></thead><tbody>';
		foreach ( $records as $record ) {
			$label = Record::KIND_USER === $record->kind ? __( 'Username', 'wp-login-limit' ) : __( 'IP', 'wp-login-limit' );
			echo '<tr><td>' . esc_html( $label ) . ': <code>' . esc_html( $record->value ) . '</code></td>';
			/* translators: %s: time span. */
			echo '<td>' . esc_html( self::format_time( $record->locked_until ) . ' (' . sprintf( __( 'in %s', 'wp-login-limit' ), human_time_diff( $now, $record->locked_until ) ) . ')' ) . '</td>';
			echo '<td>' . esc_html( (string) $record->lockouts ) . '</td>';
			echo '<td><a class="button button-small" href="' . esc_url( self::unlock_url( $record->key() ) ) . '">' . esc_html__( 'Unlock', 'wp-login-limit' ) . '</a></td></tr>';
		}
		echo '</tbody></table>';
		echo '<form method="post" action="' . esc_url( admin_url( 'admin-post.php' ) ) . '">';
		wp_nonce_field( self::UNLOCK_ALL );
		echo '<input type="hidden" name="action" value="' . esc_attr( self::UNLOCK_ALL ) . '">';
		submit_button( __( 'Unlock everyone', 'wp-login-limit' ), 'secondary', 'submit', false );
		echo '</form>';
	}

	/**
	 * Settings form.
	 */
	private function render_settings(): void {
		$s = $this->plugin->settings();

		echo '<h2>' . esc_html__( 'Settings', 'wp-login-limit' ) . '</h2>';
		echo '<form method="post" action="' . esc_url( admin_url( 'options.php' ) ) . '">';
		settings_fields( self::GROUP );
		echo '<table class="form-table" role="presentation"><tbody>';

		$this->number( 'ip_max_retries', __( 'Failed logins per IP', 'wp-login-limit' ), $s, 1, 100, __( 'Attempts allowed from one IP (IPv6: one network) within the counting window.', 'wp-login-limit' ) );
		$this->number( 'user_max_retries', __( 'Failed logins per username', 'wp-login-limit' ), $s, 0, 1000, __( 'Attempts allowed for one username from all IPs together (stops distributed attacks). 0 switches it off. Networks the user logged in from before are not affected.', 'wp-login-limit' ) );
		$this->number( 'window', __( 'Counting window (seconds)', 'wp-login-limit' ), $s, 60, 86400, __( 'Failures older than this are forgotten.', 'wp-login-limit' ) );
		$this->number( 'lockout_duration', __( 'First lockout (seconds)', 'wp-login-limit' ), $s, 60, 604800, '' );
		$this->number( 'lockout_multiplier', __( 'Each further lockout lasts', 'wp-login-limit' ), $s, 1, 10, __( 'times longer (1 = no escalation).', 'wp-login-limit' ) );
		$this->number( 'lockout_max', __( 'Longest lockout (seconds)', 'wp-login-limit' ), $s, 60, 2592000, '' );
		$this->number( 'lockout_memory', __( 'Escalation resets after (seconds)', 'wp-login-limit' ), $s, 3600, 2592000, __( 'Without a new lockout for this long, the next lockout is a first lockout again.', 'wp-login-limit' ) );
		$this->number( 'ipv6_prefix', __( 'IPv6 network size', 'wp-login-limit' ), $s, 32, 128, __( 'Prefix length counted as one client (64 by default; 128 = single addresses).', 'wp-login-limit' ) );

		$this->textarea( 'allowlist', __( 'Allowlist', 'wp-login-limit' ), $s, __( 'IP addresses or CIDR ranges, one per line. Never counted or locked out.', 'wp-login-limit' ) );
		$this->textarea( 'denylist', __( 'Denylist', 'wp-login-limit' ), $s, __( 'IP addresses or CIDR ranges, one per line. Can never log in.', 'wp-login-limit' ) );
		$this->textarea( 'deny_usernames', __( 'Lock out at once when trying', 'wp-login-limit' ), $s, __( 'Usernames that do not exist on this site, such as admin. One failed attempt with them locks the IP.', 'wp-login-limit' ) );

		$this->textarea( 'trusted_proxies', __( 'Trusted proxies', 'wp-login-limit' ), $s, __( 'Addresses or CIDR ranges of your load balancer or reverse proxy. The client IP is read from the header below only for requests from these addresses.', 'wp-login-limit' ) );
		echo '<tr><th scope="row"><label for="ll-proxy-header">' . esc_html__( 'Client IP header', 'wp-login-limit' ) . '</label></th><td>';
		echo '<select id="ll-proxy-header" name="' . esc_attr( Settings::OPTION . '[proxy_header]' ) . '">';
		foreach ( array(
			IpResolver::HEADER_XFF        => 'X-Forwarded-For',
			IpResolver::HEADER_REAL_IP    => 'X-Real-IP',
			IpResolver::HEADER_CLOUDFLARE => 'CF-Connecting-IP',
		) as $value => $label ) {
			echo '<option value="' . esc_attr( $value ) . '"' . selected( $value, (string) $s['proxy_header'], false ) . '>' . esc_html( $label ) . '</option>';
		}
		echo '</select></td></tr>';
		$this->checkbox( 'trust_cloudflare', __( 'Cloudflare', 'wp-login-limit' ), $s, __( 'Trust Cloudflare\'s published IP ranges and read CF-Connecting-IP from them.', 'wp-login-limit' ) );

		echo '<tr><th scope="row">' . esc_html__( 'XML-RPC', 'wp-login-limit' ) . '</th><td><fieldset>';
		foreach ( array(
			Settings::XMLRPC_LIMIT   => __( 'Apply the limits to XML-RPC logins', 'wp-login-limit' ),
			Settings::XMLRPC_DISABLE => __( 'Disable all XML-RPC methods that need a login (pingbacks keep working)', 'wp-login-limit' ),
		) as $value => $label ) {
			echo '<label><input type="radio" name="' . esc_attr( Settings::OPTION . '[xmlrpc]' ) . '" value="' . esc_attr( $value ) . '"' . checked( $value, (string) $s['xmlrpc'], false ) . '> ' . esc_html( $label ) . '</label><br>';
		}
		echo '</fieldset></td></tr>';

		$this->checkbox( 'generic_errors', __( 'Error messages', 'wp-login-limit' ), $s, __( 'Show one message for unknown usernames and wrong passwords, so attackers cannot find usernames.', 'wp-login-limit' ) );

		echo '<tr><th scope="row">' . esc_html__( 'Email the administrator', 'wp-login-limit' ) . '</th><td><fieldset>';
		foreach ( array(
			Settings::NOTIFY_NONE      => __( 'Never', 'wp-login-limit' ),
			Settings::NOTIFY_ESCALATED => __( 'On repeated lockouts of the same IP or username', 'wp-login-limit' ),
			Settings::NOTIFY_ALL       => __( 'On every lockout', 'wp-login-limit' ),
		) as $value => $label ) {
			echo '<label><input type="radio" name="' . esc_attr( Settings::OPTION . '[notify]' ) . '" value="' . esc_attr( $value ) . '"' . checked( $value, (string) $s['notify'], false ) . '> ' . esc_html( $label ) . '</label><br>';
		}
		echo '</fieldset></td></tr>';
		echo '<tr><th scope="row"><label for="ll-notify-email">' . esc_html__( 'Send emails to', 'wp-login-limit' ) . '</label></th><td>';
		echo '<input type="email" class="regular-text" id="ll-notify-email" name="' . esc_attr( Settings::OPTION . '[notify_email]' ) . '" value="' . esc_attr( (string) $s['notify_email'] ) . '" placeholder="' . esc_attr( (string) get_option( 'admin_email' ) ) . '"></td></tr>';
		$this->number( 'notify_interval', __( 'At most one email every (seconds)', 'wp-login-limit' ), $s, 300, 604800, __( 'Lockouts in between are counted in the next email.', 'wp-login-limit' ) );

		$this->checkbox( 'fail2ban', __( 'fail2ban', 'wp-login-limit' ), $s, __( 'Write a line for every failure, lockout and refused attempt to the PHP error log (see the README for the filter).', 'wp-login-limit' ) );
		$this->number( 'log_retention_days', __( 'Keep the lockout log for (days)', 'wp-login-limit' ), $s, 1, 3650, '' );

		echo '</tbody></table>';
		submit_button();
		echo '</form>';
	}

	/**
	 * Lockout log (latest 50).
	 */
	private function render_log(): void {
		$entries = $this->plugin->log()->recent( 50 );
		$events  = array(
			'lockout_ip'   => __( 'IP locked out', 'wp-login-limit' ),
			'lockout_user' => __( 'Username locked out', 'wp-login-limit' ),
			'denied'       => __( 'Denylisted IP refused', 'wp-login-limit' ),
			'unlock'       => __( 'Unlocked', 'wp-login-limit' ),
			'unlock_all'   => __( 'Everyone unlocked', 'wp-login-limit' ),
		);

		/* translators: %d: total number of log entries. */
		echo '<h2>' . esc_html( sprintf( __( 'Lockout log (%d)', 'wp-login-limit' ), $this->plugin->log()->count() ) ) . '</h2>';
		if ( array() === $entries ) {
			echo '<p>' . esc_html__( 'No lockouts yet.', 'wp-login-limit' ) . '</p>';
			return;
		}
		echo '<table class="widefat striped"><thead><tr>';
		foreach ( array( __( 'Time', 'wp-login-limit' ), __( 'Event', 'wp-login-limit' ), __( 'IP', 'wp-login-limit' ), __( 'Username', 'wp-login-limit' ), __( 'Via', 'wp-login-limit' ), __( 'Duration', 'wp-login-limit' ) ) as $heading ) {
			echo '<th>' . esc_html( $heading ) . '</th>';
		}
		echo '</tr></thead><tbody>';
		foreach ( $entries as $entry ) {
			$event    = (string) $entry['event'];
			$duration = (int) $entry['duration'];
			echo '<tr>';
			echo '<td>' . esc_html( self::format_time( (int) $entry['time'] ) ) . '</td>';
			echo '<td>' . esc_html( $events[ $event ] ?? $event ) . ( (int) $entry['level'] > 1 ? ' (#' . esc_html( (string) (int) $entry['level'] ) . ')' : '' ) . '</td>';
			echo '<td><code>' . esc_html( (string) $entry['ip'] ) . '</code></td>';
			echo '<td>' . esc_html( (string) $entry['username'] ) . '</td>';
			echo '<td>' . esc_html( (string) $entry['gateway'] ) . '</td>';
			echo '<td>' . ( $duration > 0 ? esc_html( human_time_diff( 0, $duration ) ) : '&mdash;' ) . '</td>';
			echo '</tr>';
		}
		echo '</tbody></table>';
		echo '<form method="post" action="' . esc_url( admin_url( 'admin-post.php' ) ) . '">';
		wp_nonce_field( self::CLEAR_LOG );
		echo '<input type="hidden" name="action" value="' . esc_attr( self::CLEAR_LOG ) . '">';
		submit_button( __( 'Clear the log', 'wp-login-limit' ), 'delete', 'submit', false );
		echo '</form>';
	}

	/**
	 * Unlock one record.
	 */
	public function handle_unlock(): void {
		$key = isset( $_GET['key'] ) ? sanitize_text_field( wp_unslash( $_GET['key'] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Verified in guard().
		$this->guard( self::UNLOCK . '_' . $key );
		$this->redirect_back( $this->plugin->limiter()->unlock_key( $key ) ? 'unlocked' : 'not_found' );
	}

	/**
	 * Unlock everyone.
	 */
	public function handle_unlock_all(): void {
		$this->guard( self::UNLOCK_ALL );
		$this->plugin->limiter()->unlock_all();
		$this->redirect_back( 'unlocked_all' );
	}

	/**
	 * Clear the lockout log.
	 */
	public function handle_clear_log(): void {
		$this->guard( self::CLEAR_LOG );
		$this->plugin->log()->clear();
		$this->redirect_back( 'log_cleared' );
	}

	/**
	 * Number field row.
	 *
	 * @param string              $key         Setting.
	 * @param string              $label       Label.
	 * @param array<string,mixed> $settings    Settings.
	 * @param int                 $min         Minimum.
	 * @param int                 $max         Maximum.
	 * @param string              $description Description.
	 */
	private function number( string $key, string $label, array $settings, int $min, int $max, string $description ): void {
		$id = 'll-' . str_replace( '_', '-', $key );
		echo '<tr><th scope="row"><label for="' . esc_attr( $id ) . '">' . esc_html( $label ) . '</label></th><td>';
		echo '<input type="number" class="small-text" id="' . esc_attr( $id ) . '" name="' . esc_attr( Settings::OPTION . '[' . $key . ']' ) . '" min="' . esc_attr( (string) $min ) . '" max="' . esc_attr( (string) $max ) . '" value="' . esc_attr( (string) $settings[ $key ] ) . '">';
		if ( '' !== $description ) {
			echo ' <span class="description">' . esc_html( $description ) . '</span>';
		}
		echo '</td></tr>';
	}

	/**
	 * Textarea row for a list setting.
	 *
	 * @param string              $key         Setting.
	 * @param string              $label       Label.
	 * @param array<string,mixed> $settings    Settings.
	 * @param string              $description Description.
	 */
	private function textarea( string $key, string $label, array $settings, string $description ): void {
		$id = 'll-' . str_replace( '_', '-', $key );
		echo '<tr><th scope="row"><label for="' . esc_attr( $id ) . '">' . esc_html( $label ) . '</label></th><td>';
		echo '<textarea class="large-text code" rows="3" id="' . esc_attr( $id ) . '" name="' . esc_attr( Settings::OPTION . '[' . $key . ']' ) . '">' . esc_textarea( implode( "\n", (array) $settings[ $key ] ) ) . '</textarea>';
		echo '<p class="description">' . esc_html( $description ) . '</p></td></tr>';
	}

	/**
	 * Checkbox row.
	 *
	 * @param string              $key         Setting.
	 * @param string              $label       Label.
	 * @param array<string,mixed> $settings    Settings.
	 * @param string              $description Checkbox text.
	 */
	private function checkbox( string $key, string $label, array $settings, string $description ): void {
		echo '<tr><th scope="row">' . esc_html( $label ) . '</th><td><label>';
		echo '<input type="checkbox" name="' . esc_attr( Settings::OPTION . '[' . $key . ']' ) . '" value="1"' . checked( ! empty( $settings[ $key ] ), true, false ) . '> ';
		echo esc_html( $description ) . '</label></td></tr>';
	}

	/**
	 * Notice for the last action.
	 */
	private function notice(): void {
		$notice   = isset( $_GET['notice'] ) ? sanitize_key( wp_unslash( $_GET['notice'] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Display only.
		$messages = array(
			'unlocked'     => __( 'Unlocked.', 'wp-login-limit' ),
			'unlocked_all' => __( 'Everyone was unlocked.', 'wp-login-limit' ),
			'not_found'    => __( 'That lockout has already ended.', 'wp-login-limit' ),
			'log_cleared'  => __( 'The lockout log is empty.', 'wp-login-limit' ),
		);
		if ( isset( $messages[ $notice ] ) ) {
			echo '<div class="notice notice-success is-dismissible"><p>' . esc_html( $messages[ $notice ] ) . '</p></div>';
		}
	}

	/**
	 * Stop unless the user may manage the plugin and the nonce is valid.
	 *
	 * @param string $action Nonce action.
	 */
	private function guard( string $action ): void {
		if ( ! current_user_can( Plugin::capability() ) ) {
			wp_die( esc_html__( 'Sorry, you are not allowed to manage login limits.', 'wp-login-limit' ), 403 );
		}
		check_admin_referer( $action );
	}

	/**
	 * Redirect back to the screen with a notice.
	 *
	 * @param string $notice Notice key.
	 */
	private function redirect_back( string $notice ): void {
		wp_safe_redirect( self::url( array( 'notice' => $notice ) ) );
		if ( apply_filters( 'login_limit_exit', true ) ) {
			exit;
		}
	}

	/**
	 * Format a Unix time in the site time zone.
	 *
	 * @param int $time Time.
	 */
	public static function format_time( int $time ): string {
		return (string) wp_date( get_option( 'date_format' ) . ' ' . get_option( 'time_format' ), $time );
	}
}
