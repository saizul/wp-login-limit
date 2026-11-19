<?php
/**
 * Plugin Name: Login Limit tweaks (example)
 * Description: Example must-use plugin showing the Login Limit hooks. Copy what you need to wp-content/mu-plugins/.
 *
 * @package Saizul\LoginLimit
 */

defined( 'ABSPATH' ) || exit;

// Send lockouts to your own monitoring (Slack webhook, SIEM, ...).
add_action(
	'login_limit_lockout',
	static function ( $lockout ) {
		do_action( 'my_monitoring_event', 'login_lockout', array(
			'reason'   => $lockout->reason,
			'ip'       => $lockout->ip,
			'username' => $lockout->username,
			'gateway'  => $lockout->gateway,
			'minutes'  => (int) ceil( $lockout->duration / 60 ),
			'level'    => $lockout->level,
		) );
	}
);

// Use a header set by a proxy the plugin does not know (here: Fastly).
// Only do this when every request really passes through that proxy.
add_filter(
	'login_limit_client_ip',
	static function ( $ip ) {
		if ( isset( $_SERVER['HTTP_FASTLY_CLIENT_IP'] ) ) {
			$candidate = sanitize_text_field( wp_unslash( $_SERVER['HTTP_FASTLY_CLIENT_IP'] ) );
			return false !== filter_var( $candidate, FILTER_VALIDATE_IP ) ? $candidate : $ip;
		}
		return $ip;
	}
);

// Only email about lockouts of real accounts.
add_filter(
	'login_limit_send_notification',
	static function ( $send, $lockout ) {
		return $send && '' !== $lockout->username && false !== get_user_by( 'login', $lockout->username );
	},
	10,
	2
);

// Let shop managers unlock customers.
add_filter(
	'login_limit_capability',
	static function () {
		return 'manage_woocommerce';
	}
);

// Write fail2ban lines to a dedicated file instead of the PHP error log.
add_filter(
	'login_limit_fail2ban_write',
	static function ( $write, $line ) {
		error_log( gmdate( '[d-M-Y H:i:s e] ' ) . $line . "\n", 3, '/var/log/wordpress/login-limit.log' ); // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log
		return false;
	},
	10,
	2
);
