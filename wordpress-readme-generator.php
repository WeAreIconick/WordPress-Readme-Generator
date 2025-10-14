<?php
/**
 * Plugin Name:       WordPress Readme Generator
 * Description:       Generate perfect WordPress.org plugin readme.txt files with visual formatting buttons and an interactive form builder that follows all official standards and best practices.
 * Version:           0.1.0
 * Requires at least: 5.0
 * Requires PHP:      7.4
 * Author:            WordPress Telex
 * License:           GPLv2 or later
 * License URI:       https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain:       wordpress-readme-generator-block-wp
 *
 * @package WordPressReadmeGenerator
 */

// Prevent direct access - Security measure
if ( ! defined( 'ABSPATH' ) ) {
	exit; // Exit if accessed directly.
}

/**
 * Registers the block using the metadata loaded from the `block.json` file.
 * Behind the scenes, it registers also all assets so they can be enqueued
 * through the block editor in the corresponding context.
 *
 * @see https://developer.wordpress.org/reference/functions/register_block_type/
 */
if ( ! function_exists( 'wordpress_readme_generator_block_init' ) ) {
	function wordpress_readme_generator_block_init() {
		register_block_type( __DIR__ . '/build/' );
	}
	add_action( 'init', 'wordpress_readme_generator_block_init' );
}

/**
 * Security: Verify nonce for AJAX requests
 *
 * @param string $action Nonce action name.
 * @return bool
 */
if ( ! function_exists( 'wordpress_readme_generator_verify_nonce' ) ) {
	function wordpress_readme_generator_verify_nonce( $action = 'wordpress_readme_generator_nonce' ) {
		$nonce = sanitize_text_field( wp_unslash( $_REQUEST['_wpnonce'] ?? '' ) );
		return wp_verify_nonce( $nonce, $action );
	}
}

/**
 * Sanitize user input with comprehensive validation
 *
 * @param mixed  $input Input to sanitize.
 * @param string $type Type of input (text, email, url, int, etc.).
 * @param int    $max_length Maximum length for string inputs.
 * @return mixed Sanitized input.
 */
if ( ! function_exists( 'wordpress_readme_generator_sanitize_input' ) ) {
	function wordpress_readme_generator_sanitize_input( $input, $type = 'text', $max_length = 0 ) {
		switch ( $type ) {
			case 'email':
				return sanitize_email( $input );
			case 'url':
				return esc_url_raw( $input );
			case 'int':
				return absint( $input );
			case 'textarea':
				$sanitized = wp_kses_post( $input );
				break;
			case 'text':
			default:
				$sanitized = sanitize_text_field( $input );
				break;
		}

		// Apply length limit if specified
		if ( $max_length > 0 && is_string( $sanitized ) ) {
			$sanitized = substr( $sanitized, 0, $max_length );
		}

		return $sanitized;
	}
}

/**
 * Log errors with context
 *
 * @param string $message Error message.
 * @param array  $context Additional context data.
 */
if ( ! function_exists( 'wordpress_readme_generator_log_error' ) ) {
	function wordpress_readme_generator_log_error( $message, $context = array() ) {
		if ( defined( 'WP_DEBUG' ) && WP_DEBUG ) {
			$log_message = 'WordPress Readme Generator: ' . $message;
			if ( ! empty( $context ) ) {
				$log_message .= ' Context: ' . wp_json_encode( $context );
			}
			error_log( $log_message );
		}
	}
}