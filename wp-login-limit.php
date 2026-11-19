<?php
/**
 * Plugin Name:       Login Limit
 * Plugin URI:        https://github.com/saizul/wp-login-limit
 * Description:       Brute-force protection without upsells: limits failed logins per IP and per username with escalating lockouts on wp-login.php, XML-RPC and REST application passwords. Trusted proxies, CIDR allow/deny lists, lockout log, throttled email alerts, fail2ban log lines and WP-CLI.
 * Version:           0.1.0
 * Requires at least: 6.2
 * Requires PHP:      7.4
 * Author:            Saizul Amin
 * Author URI:        https://saizul.com
 * License:           GPL-2.0-or-later
 * License URI:       https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain:       wp-login-limit
 * Domain Path:       /languages
 *
 * @package Saizul\LoginLimit
 */

defined( 'ABSPATH' ) || exit;

if ( PHP_VERSION_ID < 70400 ) {
	add_action(
		'admin_notices',
		static function () {
			if ( current_user_can( 'activate_plugins' ) ) {
				echo '<div class="notice notice-error"><p>' . esc_html__( 'Login Limit requires PHP 7.4 or newer.', 'wp-login-limit' ) . '</p></div>';
			}
		}
	);
	return;
}

define( 'WP_LOGIN_LIMIT_FILE', __FILE__ );
define( 'WP_LOGIN_LIMIT_VERSION', '0.1.0' );

if ( is_readable( __DIR__ . '/vendor/autoload.php' ) ) {
	require_once __DIR__ . '/vendor/autoload.php';
} else {
	// PSR-4 autoloader for installs without Composer (the release zip).
	spl_autoload_register(
		static function ( $class_name ) {
			$prefix = 'Saizul\\LoginLimit\\';
			if ( 0 !== strncmp( $class_name, $prefix, strlen( $prefix ) ) ) {
				return;
			}
			$file = __DIR__ . '/src/' . str_replace( '\\', '/', substr( $class_name, strlen( $prefix ) ) ) . '.php';
			if ( is_readable( $file ) ) {
				require_once $file;
			}
		}
	);
}

register_activation_hook( __FILE__, array( '\Saizul\LoginLimit\Plugin', 'activate' ) );
register_deactivation_hook( __FILE__, array( '\Saizul\LoginLimit\Plugin', 'deactivate' ) );

\Saizul\LoginLimit\Plugin::boot( __FILE__ );
