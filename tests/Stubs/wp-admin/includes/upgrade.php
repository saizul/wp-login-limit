<?php
/**
 * dbDelta() stub.
 *
 * @package Saizul\LoginLimit
 */

// phpcs:ignoreFile

if ( ! function_exists( 'dbDelta' ) ) {
	function dbDelta( $queries = '', $execute = true ) {
		WpStubs::$registry['dbDelta'] = (array) $queries;
		return array();
	}
}
