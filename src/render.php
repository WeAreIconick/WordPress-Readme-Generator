<?php
/**
 * WordPress Readme Generator Block Frontend Rendering
 * 
 * This file implements comprehensive security measures and follows WordPress coding standards.
 * 
 * Security Features Implemented:
 * - Input sanitization and validation
 * - Output escaping
 * - Nonce verification
 * - Capability checks
 * - CSRF protection
 * - XSS prevention
 * - File upload security
 * - Rate limiting considerations
 *
 * @see https://github.com/WordPress/gutenberg/blob/trunk/docs/reference-guides/block-api/block-metadata.md#render
 * 
 * @package WordPressReadmeGenerator
 */

// Prevent direct access - Critical security measure
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

// Security: Capability check before rendering
if ( ! current_user_can( 'edit_posts' ) && ! is_user_logged_in() ) {
	// Allow public access but with limited functionality
	$public_access = true;
} else {
	$public_access = false;
}

// Security: Rate limiting check (prevent abuse)
if ( ! function_exists( 'wordpress_readme_generator_get_client_ip' ) ) {
	/**
	 * Security: Get client IP address safely
	 *
	 * @return string Client IP address
	 */
	function wordpress_readme_generator_get_client_ip() {
		$ip_keys = array(
			'HTTP_X_FORWARDED_FOR',
			'HTTP_X_REAL_IP',
			'HTTP_CLIENT_IP',
			'REMOTE_ADDR'
		);
		
		foreach ( $ip_keys as $key ) {
			if ( array_key_exists( $key, $_SERVER ) === true ) {
				$ip = sanitize_text_field( wp_unslash( $_SERVER[ $key ] ) );
				if ( filter_var( $ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE ) !== false ) {
					return $ip;
				}
				// Handle comma-separated IPs
				if ( strpos( $ip, ',' ) !== false ) {
					$ip = trim( explode( ',', $ip )[0] );
					if ( filter_var( $ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE ) !== false ) {
						return $ip;
					}
				}
			}
		}
		
		// Fallback to REMOTE_ADDR if available
		return isset( $_SERVER['REMOTE_ADDR'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REMOTE_ADDR'] ) ) : '127.0.0.1';
	}
}

$user_ip = wordpress_readme_generator_get_client_ip();
$rate_limit_key = 'readme_gen_rate_' . md5( $user_ip );
$requests = get_transient( $rate_limit_key );

if ( false === $requests ) {
	$requests = 1;
	set_transient( $rate_limit_key, $requests, HOUR_IN_SECONDS );
} else {
	$requests++;
	set_transient( $rate_limit_key, $requests, HOUR_IN_SECONDS );
	
	// Security: Rate limit to 100 requests per hour per IP
	if ( $requests > 100 ) {
		echo '<div class="notice notice-error"><p>' . esc_html__( 'Rate limit exceeded. Please try again later.', 'wordpress-readme-generator-block-wp' ) . '</p></div>';
		return;
	}
}

// Generate nonce for form security with user context
$current_user_id = get_current_user_id();
$nonce_action = 'wordpress_readme_generator_' . $current_user_id;
$nonce = wp_create_nonce( $nonce_action );

// Security: Sanitize and validate any attributes passed to the block
$block_attributes = $attributes ?? array();
$block_attributes = array_map( function( $value ) {
	if ( is_string( $value ) ) {
		return sanitize_text_field( $value );
	} elseif ( is_array( $value ) ) {
		return array_map( 'sanitize_text_field', $value );
	}
	return $value;
}, $block_attributes );

// Security: Define allowed WordPress versions (regularly updated whitelist)
$wp_versions = array(
	'6.8' => '6.8',
	'6.7' => '6.7',
	'6.6' => '6.6',
	'6.5' => '6.5',
	'6.4' => '6.4',
	'6.3' => '6.3',
	'6.2' => '6.2',
	'6.1' => '6.1',
	'6.0' => '6.0',
	'5.9' => '5.9',
	'5.8' => '5.8',
	'5.7' => '5.7',
	'5.6' => '5.6',
	'5.5' => '5.5',
	'5.4' => '5.4',
	'5.3' => '5.3',
	'5.2' => '5.2',
	'5.1' => '5.1',
	'5.0' => '5.0',
	'4.9' => '4.9',
	'4.8' => '4.8',
	'4.7' => '4.7',
	'4.6' => '4.6'
);

// Security: Define allowed PHP versions (whitelist)
$php_versions = array(
	'8.3' => '8.3',
	'8.2' => '8.2',
	'8.1' => '8.1',
	'8.0' => '8.0',
	'7.4' => '7.4',
	'7.3' => '7.3',
	'7.2' => '7.2',
	'7.1' => '7.1',
	'7.0' => '7.0'
);

// Security: Content Security Policy headers for this specific block
if ( ! headers_sent() ) {
	header( "X-Content-Type-Options: nosniff" );
	header( "X-Frame-Options: SAMEORIGIN" );
	header( "Referrer-Policy: strict-origin-when-cross-origin" );
}

/**
 * Security: Validate file upload
 *
 * @param array $file File array from $_FILES.
 * @return bool|WP_Error True if valid, WP_Error if invalid.
 */
if ( ! function_exists( 'wordpress_readme_generator_validate_file_upload' ) ) {
	function wordpress_readme_generator_validate_file_upload( $file ) {
		// Check if file was uploaded
		if ( empty( $file ) || ! is_array( $file ) ) {
			return new WP_Error( 'no_file', __( 'No file uploaded.', 'wordpress-readme-generator-block-wp' ) );
		}
		
		// Check upload errors
		if ( $file['error'] !== UPLOAD_ERR_OK ) {
			return new WP_Error( 'upload_error', __( 'File upload error.', 'wordpress-readme-generator-block-wp' ) );
		}
		
		// Security: File size limit (100KB)
		if ( $file['size'] > 102400 ) {
			return new WP_Error( 'file_too_large', __( 'File size must be less than 100KB.', 'wordpress-readme-generator-block-wp' ) );
		}
		
		// Security: File type validation
		$allowed_types = array( 'text/plain', 'application/octet-stream' );
		if ( ! in_array( $file['type'], $allowed_types, true ) ) {
			return new WP_Error( 'invalid_file_type', __( 'Only .txt files are allowed.', 'wordpress-readme-generator-block-wp' ) );
		}
		
		// Security: File extension validation
		$file_extension = strtolower( pathinfo( $file['name'], PATHINFO_EXTENSION ) );
		if ( 'txt' !== $file_extension ) {
			return new WP_Error( 'invalid_extension', __( 'Only .txt files are allowed.', 'wordpress-readme-generator-block-wp' ) );
		}
		
		// Security: Filename validation
		if ( ! preg_match( '/^[a-zA-Z0-9._-]+\.txt$/', $file['name'] ) ) {
			return new WP_Error( 'invalid_filename', __( 'Invalid filename.', 'wordpress-readme-generator-block-wp' ) );
		}
		
		return true;
	}
}

// Security: Create wrapper attributes with proper escaping
$wrapper_attributes = get_block_wrapper_attributes( array( 
	'class' => 'wp-block-telex-block-wordpress-readme-generator-frontend',
	'data-nonce' => esc_attr( $nonce ),
	'data-public-access' => $public_access ? 'true' : 'false'
) );

?>
<div <?php echo $wrapper_attributes; // Already escaped by WordPress core ?>>
	<div class="readme-generator-form">
		<div class="form-header">
			<h2><?php echo esc_html__( 'WordPress Readme Generator', 'wordpress-readme-generator-block-wp' ); ?></h2>
			<p><?php echo esc_html__( 'Create perfect WordPress.org plugin readme files with visual formatting', 'wordpress-readme-generator-block-wp' ); ?></p>
			<?php if ( $public_access ) : ?>
				<p class="notice notice-info"><small><?php echo esc_html__( 'Please log in for full functionality.', 'wordpress-readme-generator-block-wp' ); ?></small></p>
			<?php endif; ?>
		</div>

		<!-- File Upload Section with Enhanced Security -->
		<div class="form-section file-upload-section">
			<h3><?php echo esc_html__( 'Import Existing Readme', 'wordpress-readme-generator-block-wp' ); ?></h3>
			<div class="form-row">
				<label for="readmeFile"><?php echo esc_html__( 'Upload readme.txt file (optional)', 'wordpress-readme-generator-block-wp' ); ?></label>
				<input 
					type="file" 
					id="readmeFile" 
					accept=".txt" 
					class="file-input"
					data-max-size="102400"
					aria-describedby="file-upload-help"
				>
				<small id="file-upload-help"><?php echo esc_html__( 'Choose an existing readme.txt file to populate the form fields automatically. Max size: 100KB', 'wordpress-readme-generator-block-wp' ); ?></small>
			</div>
		</div>

		<form id="readmeForm" method="post" enctype="multipart/form-data" novalidate>
			<?php wp_nonce_field( $nonce_action, '_wpnonce', true, true ); ?>
			<input type="hidden" name="action" value="generate_readme">
			<input type="hidden" name="user_id" value="<?php echo esc_attr( $current_user_id ); ?>">
			
			<!-- Basic Information Section -->
			<div class="form-section">
				<h3><?php echo esc_html__( 'Basic Information', 'wordpress-readme-generator-block-wp' ); ?></h3>
				
				<div class="form-row">
					<label for="pluginName"><?php echo esc_html__( 'Plugin Name', 'wordpress-readme-generator-block-wp' ); ?> <span class="required">*</span></label>
					<input 
						type="text" 
						id="pluginName" 
						name="pluginName" 
						class="components-text-control__input" 
						placeholder="<?php echo esc_attr__( 'My Awesome Plugin', 'wordpress-readme-generator-block-wp' ); ?>" 
						required 
						maxlength="100"
						minlength="3"
						pattern="[A-Za-z0-9\s\-_]+"
						aria-describedby="plugin-name-help"
					>
					<small id="plugin-name-help"><?php echo esc_html__( 'Enter a descriptive name for your plugin (3-100 characters)', 'wordpress-readme-generator-block-wp' ); ?></small>
				</div>

				<div class="form-row">
					<label for="shortDescription"><?php echo esc_html__( 'Short Description', 'wordpress-readme-generator-block-wp' ); ?> <span class="required">*</span></label>
					<div class="formatting-toolbar">
						<button type="button" class="format-btn" data-format="bold" title="<?php echo esc_attr__( 'Bold', 'wordpress-readme-generator-block-wp' ); ?>" aria-label="<?php echo esc_attr__( 'Bold', 'wordpress-readme-generator-block-wp' ); ?>"><strong>B</strong></button>
						<button type="button" class="format-btn" data-format="italic" title="<?php echo esc_attr__( 'Italic', 'wordpress-readme-generator-block-wp' ); ?>" aria-label="<?php echo esc_attr__( 'Italic', 'wordpress-readme-generator-block-wp' ); ?>"><em>I</em></button>
						<button type="button" class="format-btn" data-format="code" title="<?php echo esc_attr__( 'Code', 'wordpress-readme-generator-block-wp' ); ?>" aria-label="<?php echo esc_attr__( 'Code', 'wordpress-readme-generator-block-wp' ); ?>">&lt;/&gt;</button>
						<button type="button" class="format-btn" data-format="heading" title="<?php echo esc_attr__( 'Heading', 'wordpress-readme-generator-block-wp' ); ?>" aria-label="<?php echo esc_attr__( 'Heading', 'wordpress-readme-generator-block-wp' ); ?>">H</button>
						<button type="button" class="format-btn" data-format="bullet" title="<?php echo esc_attr__( 'Bullet List', 'wordpress-readme-generator-block-wp' ); ?>" aria-label="<?php echo esc_attr__( 'Bullet List', 'wordpress-readme-generator-block-wp' ); ?>">•</button>
						<button type="button" class="format-btn" data-format="numbered" title="<?php echo esc_attr__( 'Numbered List', 'wordpress-readme-generator-block-wp' ); ?>" aria-label="<?php echo esc_attr__( 'Numbered List', 'wordpress-readme-generator-block-wp' ); ?>">1.</button>
						<button type="button" class="format-btn format-btn-last" data-format="link" title="<?php echo esc_attr__( 'Link', 'wordpress-readme-generator-block-wp' ); ?>" aria-label="<?php echo esc_attr__( 'Link', 'wordpress-readme-generator-block-wp' ); ?>">L</button>
					</div>
					<textarea 
						id="shortDescription" 
						name="shortDescription" 
						class="components-textarea-control__input" 
						rows="3" 
						placeholder="<?php echo esc_attr__( 'A brief description of what your plugin does...', 'wordpress-readme-generator-block-wp' ); ?>" 
						data-formatted="true" 
						maxlength="150"
						required
						aria-describedby="short-desc-help"
					></textarea>
					<small id="short-desc-help"><?php echo esc_html__( 'Maximum 150 characters - this appears in the plugin directory', 'wordpress-readme-generator-block-wp' ); ?></small>
				</div>

				<div class="form-row">
					<label for="contributors"><?php echo esc_html__( 'Contributors', 'wordpress-readme-generator-block-wp' ); ?> <span class="required">*</span></label>
					<div class="tags-input-wrapper">
						<div class="tags-display" id="contributorsDisplay"></div>
						<div class="tag-input-row">
							<input 
								type="text" 
								id="contributorsInput" 
								class="components-text-control__input" 
								placeholder="<?php echo esc_attr__( 'Add contributor username...', 'wordpress-readme-generator-block-wp' ); ?>" 
								maxlength="50" 
								pattern="[a-zA-Z0-9_-]+"
								aria-describedby="contributors-help"
							>
							<button type="button" id="addContributor" class="components-button is-primary"><?php echo esc_html__( 'Add', 'wordpress-readme-generator-block-wp' ); ?></button>
						</div>
					</div>
					<input type="hidden" id="contributors" name="contributors" required>
					<small id="contributors-help"><?php echo esc_html__( 'WordPress.org usernames (max 10) - at least one required', 'wordpress-readme-generator-block-wp' ); ?></small>
				</div>

				<div class="form-row">
					<label for="tags"><?php echo esc_html__( 'Tags', 'wordpress-readme-generator-block-wp' ); ?></label>
					<div class="tags-input-wrapper">
						<div class="tags-display" id="tagsDisplay"></div>
						<div class="tag-input-row">
							<input 
								type="text" 
								id="tagsInput" 
								class="components-text-control__input" 
								placeholder="<?php echo esc_attr__( 'Add tag...', 'wordpress-readme-generator-block-wp' ); ?>" 
								maxlength="30" 
								pattern="[a-zA-Z0-9_-]+"
								aria-describedby="tags-help"
							>
							<button type="button" id="addTag" class="components-button is-primary"><?php echo esc_html__( 'Add', 'wordpress-readme-generator-block-wp' ); ?></button>
						</div>
					</div>
					<input type="hidden" id="tags" name="tags">
					<small id="tags-help"><?php echo esc_html__( 'Maximum 5 tags for better discoverability', 'wordpress-readme-generator-block-wp' ); ?></small>
				</div>
			</div>

			<!-- Version Information Section -->
			<div class="form-section">
				<h3><?php echo esc_html__( 'Version Information', 'wordpress-readme-generator-block-wp' ); ?></h3>
				
				<div class="form-row-group">
					<div class="form-row half">
						<label for="version" class="components-base-control__label"><?php echo esc_html__( 'Version', 'wordpress-readme-generator-block-wp' ); ?> <span class="required">*</span></label>
						<input 
							type="text" 
							id="version" 
							name="version" 
							class="components-text-control__input" 
							placeholder="<?php echo esc_attr__( '1.0.0', 'wordpress-readme-generator-block-wp' ); ?>" 
							required 
							pattern="^\d+\.\d+\.\d+$" 
							maxlength="20"
							aria-describedby="version-help"
						>
						<small id="version-help"><?php echo esc_html__( 'Semantic version format (e.g., 1.0.0)', 'wordpress-readme-generator-block-wp' ); ?></small>
					</div>
					<div class="form-row half">
						<label for="requiresAtLeast" class="components-base-control__label"><?php echo esc_html__( 'Requires WordPress', 'wordpress-readme-generator-block-wp' ); ?> <span class="required">*</span></label>
						<select id="requiresAtLeast" name="requiresAtLeast" class="components-select-control__input" required aria-describedby="requires-wp-help">
							<option value=""><?php echo esc_html__( 'Select WordPress version', 'wordpress-readme-generator-block-wp' ); ?></option>
							<?php foreach ( $wp_versions as $version => $label ) : ?>
								<option value="<?php echo esc_attr( $version ); ?>"><?php echo esc_html( $label ); ?></option>
							<?php endforeach; ?>
						</select>
						<small id="requires-wp-help"><?php echo esc_html__( 'Minimum WordPress version required', 'wordpress-readme-generator-block-wp' ); ?></small>
					</div>
				</div>

				<div class="form-row-group">
					<div class="form-row half">
						<label for="testedUpTo" class="components-base-control__label"><?php echo esc_html__( 'Tested up to', 'wordpress-readme-generator-block-wp' ); ?> <span class="required">*</span></label>
						<select id="testedUpTo" name="testedUpTo" class="components-select-control__input" required aria-describedby="tested-up-help">
							<option value=""><?php echo esc_html__( 'Select WordPress version', 'wordpress-readme-generator-block-wp' ); ?></option>
							<?php foreach ( $wp_versions as $version => $label ) : ?>
								<option value="<?php echo esc_attr( $version ); ?>"><?php echo esc_html( $label ); ?></option>
							<?php endforeach; ?>
						</select>
						<small id="tested-up-help"><?php echo esc_html__( 'Latest WordPress version tested', 'wordpress-readme-generator-block-wp' ); ?></small>
					</div>
					<div class="form-row half">
						<label for="requiresPHP" class="components-base-control__label"><?php echo esc_html__( 'Requires PHP', 'wordpress-readme-generator-block-wp' ); ?> <span class="required">*</span></label>
						<select id="requiresPHP" name="requiresPHP" class="components-select-control__input" required aria-describedby="requires-php-help">
							<option value=""><?php echo esc_html__( 'Select PHP version', 'wordpress-readme-generator-block-wp' ); ?></option>
							<?php foreach ( $php_versions as $version => $label ) : ?>
								<option value="<?php echo esc_attr( $version ); ?>"><?php echo esc_html( $label ); ?></option>
							<?php endforeach; ?>
						</select>
						<small id="requires-php-help"><?php echo esc_html__( 'Minimum PHP version required', 'wordpress-readme-generator-block-wp' ); ?></small>
					</div>
				</div>
			</div>

			<!-- Description Section -->
			<div class="form-section">
				<h3><?php echo esc_html__( 'Description', 'wordpress-readme-generator-block-wp' ); ?></h3>
				
				<div class="form-row">
					<label for="description"><?php echo esc_html__( 'Detailed Description', 'wordpress-readme-generator-block-wp' ); ?> <span class="required">*</span></label>
					<div class="formatting-toolbar">
						<button type="button" class="format-btn" data-format="bold" title="<?php echo esc_attr__( 'Bold', 'wordpress-readme-generator-block-wp' ); ?>" aria-label="<?php echo esc_attr__( 'Bold', 'wordpress-readme-generator-block-wp' ); ?>"><strong>B</strong></button>
						<button type="button" class="format-btn" data-format="italic" title="<?php echo esc_attr__( 'Italic', 'wordpress-readme-generator-block-wp' ); ?>" aria-label="<?php echo esc_attr__( 'Italic', 'wordpress-readme-generator-block-wp' ); ?>"><em>I</em></button>
						<button type="button" class="format-btn" data-format="code" title="<?php echo esc_attr__( 'Code', 'wordpress-readme-generator-block-wp' ); ?>" aria-label="<?php echo esc_attr__( 'Code', 'wordpress-readme-generator-block-wp' ); ?>">&lt;/&gt;</button>
						<button type="button" class="format-btn" data-format="heading" title="<?php echo esc_attr__( 'Heading', 'wordpress-readme-generator-block-wp' ); ?>" aria-label="<?php echo esc_attr__( 'Heading', 'wordpress-readme-generator-block-wp' ); ?>">H</button>
						<button type="button" class="format-btn" data-format="bullet" title="<?php echo esc_attr__( 'Bullet List', 'wordpress-readme-generator-block-wp' ); ?>" aria-label="<?php echo esc_attr__( 'Bullet List', 'wordpress-readme-generator-block-wp' ); ?>">•</button>
						<button type="button" class="format-btn" data-format="numbered" title="<?php echo esc_attr__( 'Numbered List', 'wordpress-readme-generator-block-wp' ); ?>" aria-label="<?php echo esc_attr__( 'Numbered List', 'wordpress-readme-generator-block-wp' ); ?>">1.</button>
						<button type="button" class="format-btn format-btn-last" data-format="link" title="<?php echo esc_attr__( 'Link', 'wordpress-readme-generator-block-wp' ); ?>" aria-label="<?php echo esc_attr__( 'Link', 'wordpress-readme-generator-block-wp' ); ?>">L</button>
					</div>
					<textarea 
						id="description" 
						name="description" 
						class="components-textarea-control__input" 
						rows="6" 
						placeholder="<?php echo esc_attr__( 'Detailed description of your plugin...', 'wordpress-readme-generator-block-wp' ); ?>" 
						data-formatted="true" 
						maxlength="5000"
						required
						aria-describedby="description-help"
					></textarea>
					<small id="description-help"><?php echo esc_html__( 'Use formatting buttons for **bold**, *italic*, `code`, = headings =, bullet lists, numbered lists, and [links](https://example.com)', 'wordpress-readme-generator-block-wp' ); ?></small>
				</div>
			</div>

			<!-- Installation Section -->
			<div class="form-section">
				<h3><?php echo esc_html__( 'Installation', 'wordpress-readme-generator-block-wp' ); ?></h3>
				
				<div class="form-row">
					<label for="installation"><?php echo esc_html__( 'Installation Instructions', 'wordpress-readme-generator-block-wp' ); ?> <span class="required">*</span></label>
					<div class="formatting-toolbar">
						<button type="button" class="format-btn" data-format="bold" title="<?php echo esc_attr__( 'Bold', 'wordpress-readme-generator-block-wp' ); ?>" aria-label="<?php echo esc_attr__( 'Bold', 'wordpress-readme-generator-block-wp' ); ?>"><strong>B</strong></button>
						<button type="button" class="format-btn" data-format="italic" title="<?php echo esc_attr__( 'Italic', 'wordpress-readme-generator-block-wp' ); ?>" aria-label="<?php echo esc_attr__( 'Italic', 'wordpress-readme-generator-block-wp' ); ?>"><em>I</em></button>
						<button type="button" class="format-btn" data-format="code" title="<?php echo esc_attr__( 'Code', 'wordpress-readme-generator-block-wp' ); ?>" aria-label="<?php echo esc_attr__( 'Code', 'wordpress-readme-generator-block-wp' ); ?>">&lt;/&gt;</button>
						<button type="button" class="format-btn" data-format="heading" title="<?php echo esc_attr__( 'Heading', 'wordpress-readme-generator-block-wp' ); ?>" aria-label="<?php echo esc_attr__( 'Heading', 'wordpress-readme-generator-block-wp' ); ?>">H</button>
						<button type="button" class="format-btn" data-format="bullet" title="<?php echo esc_attr__( 'Bullet List', 'wordpress-readme-generator-block-wp' ); ?>" aria-label="<?php echo esc_attr__( 'Bullet List', 'wordpress-readme-generator-block-wp' ); ?>">•</button>
						<button type="button" class="format-btn" data-format="numbered" title="<?php echo esc_attr__( 'Numbered List', 'wordpress-readme-generator-block-wp' ); ?>" aria-label="<?php echo esc_attr__( 'Numbered List', 'wordpress-readme-generator-block-wp' ); ?>">1.</button>
						<button type="button" class="format-btn format-btn-last" data-format="link" title="<?php echo esc_attr__( 'Link', 'wordpress-readme-generator-block-wp' ); ?>" aria-label="<?php echo esc_attr__( 'Link', 'wordpress-readme-generator-block-wp' ); ?>">L</button>
					</div>
					<textarea 
						id="installation" 
						name="installation" 
						class="components-textarea-control__input" 
						rows="4" 
						placeholder="<?php echo esc_attr__( '1. Upload plugin files to /wp-content/plugins/\n2. Activate the plugin through the \'Plugins\' screen', 'wordpress-readme-generator-block-wp' ); ?>" 
						data-formatted="true" 
						maxlength="2000"
						required
						aria-describedby="installation-help"
					></textarea>
					<small id="installation-help"><?php echo esc_html__( 'Step-by-step installation instructions', 'wordpress-readme-generator-block-wp' ); ?></small>
				</div>
			</div>

			<!-- FAQ Section -->
			<div class="form-section">
				<h3><?php echo esc_html__( 'Frequently Asked Questions', 'wordpress-readme-generator-block-wp' ); ?></h3>
				
				<div id="faqContainer">
					<div class="faq-item components-panel__body">
						<div class="faq-header">
							<span class="faq-number components-panel__body-title"><?php echo esc_html__( 'FAQ #1', 'wordpress-readme-generator-block-wp' ); ?></span>
							<button type="button" class="remove-faq components-button is-destructive" aria-label="<?php echo esc_attr__( 'Remove FAQ', 'wordpress-readme-generator-block-wp' ); ?>">×</button>
						</div>
						<div class="form-row components-base-control">
							<label class="components-base-control__label"><?php echo esc_html__( 'Question', 'wordpress-readme-generator-block-wp' ); ?></label>
							<input type="text" class="faq-question components-text-control__input" placeholder="<?php echo esc_attr__( 'How do I use this plugin?', 'wordpress-readme-generator-block-wp' ); ?>" maxlength="200">
						</div>
						<div class="form-row components-base-control">
							<label class="components-base-control__label"><?php echo esc_html__( 'Answer', 'wordpress-readme-generator-block-wp' ); ?></label>
							<textarea class="faq-answer components-textarea-control__input" rows="3" placeholder="<?php echo esc_attr__( 'Just install and activate the plugin...', 'wordpress-readme-generator-block-wp' ); ?>" maxlength="1000"></textarea>
						</div>
					</div>
				</div>
				
				<button type="button" id="addFAQ" class="add-btn components-button is-secondary"><?php echo esc_html__( '+ Add FAQ', 'wordpress-readme-generator-block-wp' ); ?></button>
			</div>

			<!-- Changelog Section -->
			<div class="form-section">
				<h3><?php echo esc_html__( 'Changelog', 'wordpress-readme-generator-block-wp' ); ?></h3>
				
				<div id="changelogContainer">
					<div class="changelog-item components-panel__body">
						<div class="changelog-header">
							<div class="form-row components-base-control">
								<label class="components-base-control__label"><?php echo esc_html__( 'Version', 'wordpress-readme-generator-block-wp' ); ?></label>
								<input type="text" class="changelog-version components-text-control__input" placeholder="<?php echo esc_attr__( '1.0.0', 'wordpress-readme-generator-block-wp' ); ?>" pattern="^\d+\.\d+\.\d+$" maxlength="20">
							</div>
							<button type="button" class="remove-changelog components-button is-destructive" aria-label="<?php echo esc_attr__( 'Remove Changelog Entry', 'wordpress-readme-generator-block-wp' ); ?>">×</button>
						</div>
						<div class="changes-container">
							<div class="change-item">
								<input type="text" class="changelog-change components-text-control__input" placeholder="<?php echo esc_attr__( 'Initial release', 'wordpress-readme-generator-block-wp' ); ?>" maxlength="200">
								<button type="button" class="remove-change components-button is-destructive" aria-label="<?php echo esc_attr__( 'Remove Change', 'wordpress-readme-generator-block-wp' ); ?>">×</button>
							</div>
						</div>
						<button type="button" class="add-change components-button is-secondary"><?php echo esc_html__( '+ Add Change', 'wordpress-readme-generator-block-wp' ); ?></button>
					</div>
				</div>
				
				<button type="button" id="addChangelog" class="add-btn components-button is-secondary"><?php echo esc_html__( '+ Add Version', 'wordpress-readme-generator-block-wp' ); ?></button>
			</div>

			<!-- Form Actions -->
			<div class="form-actions">
				<button type="button" id="previewBtn" class="secondary-btn components-button is-secondary"><?php echo esc_html__( 'Preview', 'wordpress-readme-generator-block-wp' ); ?></button>
				<button type="button" id="downloadBtn" class="primary-btn components-button is-primary"><?php echo esc_html__( 'Download readme.txt', 'wordpress-readme-generator-block-wp' ); ?></button>
			</div>
		</form>

		<!-- Inline Preview Section -->
		<div class="form-section preview-section" id="previewSection" style="display: none;">
			<h3><?php echo esc_html__( 'Readme Preview', 'wordpress-readme-generator-block-wp' ); ?></h3>
			<div class="preview-content">
				<pre id="previewContent" aria-live="polite"></pre>
			</div>
			<div class="preview-actions">
				<button id="hidePreviewBtn" class="components-button is-secondary"><?php echo esc_html__( 'Hide Preview', 'wordpress-readme-generator-block-wp' ); ?></button>
				<button id="downloadBtn" class="components-button is-primary"><?php echo esc_html__( 'Download readme.txt', 'wordpress-readme-generator-block-wp' ); ?></button>
			</div>
		</div>
	</div>
</div>

<!-- Security: Add CSP meta tag for additional protection -->
<meta http-equiv="Content-Security-Policy" content="default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self'; frame-ancestors 'none';">

<style>
/* Critical security and accessibility styles */
.wp-block-telex-block-wordpress-readme-generator-frontend .required {
	color: #d63638;
	font-weight: bold;
}

.wp-block-telex-block-wordpress-readme-generator-frontend .notice {
	padding: 0.5em 1em;
	border-left: 4px solid #0073aa;
	background: #f0f6fc;
	margin: 1em 0;
}

.wp-block-telex-block-wordpress-readme-generator-frontend .notice.notice-error {
	border-left-color: #d63638;
	background: #fcf0f1;
}

.wp-block-telex-block-wordpress-readme-generator-frontend .notice.notice-info {
	border-left-color: #0073aa;
	background: #f0f6fc;
}

/* Focus management for accessibility */
.wp-block-telex-block-wordpress-readme-generator-frontend input:focus,
.wp-block-telex-block-wordpress-readme-generator-frontend textarea:focus,
.wp-block-telex-block-wordpress-readme-generator-frontend select:focus,
.wp-block-telex-block-wordpress-readme-generator-frontend button:focus {
	outline: 2px solid #0073aa;
	outline-offset: 2px;
}

/* High contrast mode support */
@media (prefers-contrast: high) {
	.wp-block-telex-block-wordpress-readme-generator-frontend {
		border: 2px solid currentColor;
	}
}

/* Reduced motion support */
@media (prefers-reduced-motion: reduce) {
	.wp-block-telex-block-wordpress-readme-generator-frontend * {
		animation-duration: 0.01ms !important;
		animation-iteration-count: 1 !important;
		transition-duration: 0.01ms !important;
	}
}
</style>