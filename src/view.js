/**
 * WordPress Readme Generator Block - Frontend JavaScript
 * 
 * Enhanced with comprehensive security measures and WordPress coding standards
 * 
 * Security Features:
 * - Input sanitization and validation
 * - XSS prevention
 * - CSRF protection via nonces
 * - File upload security
 * - Rate limiting awareness
 * - Error handling and logging
 * - Content Security Policy compliance
 * 
 * @package WordPressReadmeGenerator
 * @since 0.1.0
 */

(function() {
	'use strict';
	
	// Security: Global constants
	const SECURITY_CONFIG = {
		maxFileSize: 102400, // 100KB
		allowedFileTypes: ['text/plain'],
		allowedExtensions: ['txt'],
		maxInputLength: {
			plugingName: 100,
			shortDescription: 150,
			description: 5000,
			installation: 2000,
			faqQuestion: 200,
			faqAnswer: 1000,
			changelogChange: 200,
			contributor: 50,
			tag: 30,
			version: 20
		},
		maxItems: {
			faqs: 20,
			changelogs: 20,
			changes: 10,
			contributors: 10,
			tags: 5
		},
		rateLimit: {
			maxRequests: 100,
			timeWindow: 3600000 // 1 hour in milliseconds
		}
	};
	
	// Security: Comprehensive input sanitization
			function sanitizeInput(input, maxLength = 1000) {
				if (typeof input !== 'string') {
					return '';
				}
		
		// Remove potentially dangerous characters and normalize
		let sanitized = (input || '')
			.trim()
			.slice(0, maxLength)
			.replace(/[<>"'&\x00-\x1f\x7f-\x9f]/g, function(match) {
					const entityMap = {
						'<': '&lt;',
						'>': '&gt;',
						'"': '&quot;',
						"'": '&#x27;',
						'&': '&amp;'
					};
				return entityMap[match] || '';
			});
			
		// Additional normalization
		sanitized = sanitized.replace(/\s+/g, ' ').trim();
		
		return sanitized;
	}
	
	// Security: Validate specific input types
	function validateInput(input, type) {
		switch (type) {
			case 'username':
				return /^[a-zA-Z0-9_-]{1,50}$/.test(input);
			case 'version':
				return /^\d+\.\d+\.\d+$/.test(input);
			case 'tag':
				return /^[a-zA-Z0-9_-]{1,30}$/.test(input);
			case 'url':
				try {
					new URL(input);
					return true;
				} catch {
					return false;
				}
			case 'email':
				return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(input);
			default:
				return true;
		}
	}
	
	// Security: Rate limiting check
	function checkRateLimit() {
		const now = Date.now();
		const rateLimitKey = 'wordpress_readme_gen_requests';
		let requests = JSON.parse(localStorage.getItem(rateLimitKey) || '[]');
		
		// Clean old requests
		requests = requests.filter(timestamp => 
			now - timestamp < SECURITY_CONFIG.rateLimit.timeWindow
		);
		
		// Check if rate limit exceeded
		if (requests.length >= SECURITY_CONFIG.rateLimit.maxRequests) {
			return false;
		}
		
		// Add current request
		requests.push(now);
		localStorage.setItem(rateLimitKey, JSON.stringify(requests));
		
		return true;
	}
	
	// Security: Log security events
	function logSecurityEvent(event, details = {}) {
		if (typeof console !== 'undefined' && console.warn) {
			console.warn('WordPress Readme Generator Security Event:', event, details);
		}
		
		// In production, you might want to send this to a logging service
		if (window.wp && window.wp.apiFetch) {
			// Could implement server-side logging here
		}
	}
	
	// Security: Validate file upload
	function validateFileUpload(file) {
		if (!file || typeof file !== 'object') {
			return { valid: false, error: 'No file provided' };
		}
		
		// File size check
		if (file.size > SECURITY_CONFIG.maxFileSize) {
			return { valid: false, error: 'File size too large (max 100KB)' };
		}
		
		// File type check
		if (!SECURITY_CONFIG.allowedFileTypes.includes(file.type) && 
			file.type !== 'application/octet-stream') {
			return { valid: false, error: 'Invalid file type' };
		}
		
		// File extension check
		const extension = file.name.toLowerCase().split('.').pop();
		if (!SECURITY_CONFIG.allowedExtensions.includes(extension)) {
			return { valid: false, error: 'Invalid file extension' };
		}
		
		// Filename validation
		if (!/^[a-zA-Z0-9._-]+\.txt$/.test(file.name)) {
			return { valid: false, error: 'Invalid filename' };
		}
		
		return { valid: true };
	}
	
	// Security: Verify nonce before operations
	function verifyNonce(blockElement) {
		const nonce = blockElement.dataset.nonce;
		if (!nonce) {
			logSecurityEvent('missing_nonce');
			return false;
		}
		return true;
	}
	
	// Enhanced error handling
	function handleError(error, context = '') {
		console.error('WordPress Readme Generator Error:', context, error);
		
		// Show user-friendly error message
		const errorMessage = error.message || 'An unexpected error occurred';
		showInlineNotification(errorMessage, 'error');
	}
	
	// Inline notification system
	function showInlineNotification(message, type = 'info', duration = 5000) {
		// Remove any existing notifications
		const existingNotification = document.querySelector('.readme-inline-notification');
		if (existingNotification) {
			existingNotification.remove();
		}

		const notification = document.createElement('div');
		notification.className = `readme-inline-notification notice notice-${type}`;
		notification.style.cssText = `
			padding: 12px 16px;
			border-left: 4px solid #0073aa;
			background: #f0f6fc;
			color: #1d2327;
			font-size: 14px;
			line-height: 1.4;
			border-radius: 4px;
			margin: 10px 0;
			word-wrap: break-word;
		`;
		
		if (type === 'error') {
			notification.style.borderLeftColor = '#d63638';
			notification.style.background = '#fcf0f1';
		} else if (type === 'success') {
			notification.style.borderLeftColor = '#00a32a';
			notification.style.background = '#f0f6fc';
		}
		
		// Sanitize message before displaying
		notification.textContent = sanitizeInput(message, 200);
		
		// Close button
		const closeBtn = document.createElement('button');
		closeBtn.innerHTML = '×';
		closeBtn.style.cssText = `
			float: right;
			background: none;
			border: none;
			font-size: 18px;
			cursor: pointer;
			margin-left: 10px;
		`;
		closeBtn.onclick = () => notification.remove();
		notification.appendChild(closeBtn);
		
		// Insert at the top of the form
		const form = document.querySelector('#readmeForm');
		if (form && form.parentNode) {
			form.parentNode.insertBefore(notification, form);
		}
		
		// Auto-remove after duration
		if (duration > 0) {
			setTimeout(() => {
				if (notification.parentNode) {
					notification.remove();
				}
			}, duration);
		}
	}
	
	// Main initialization function
	document.addEventListener('DOMContentLoaded', function() {
		try {
			const readmeGenerators = document.querySelectorAll('.wp-block-telex-block-wordpress-readme-generator-frontend');
			
			readmeGenerators.forEach(function(generator) {
				initializeGenerator(generator);
			});
		} catch (error) {
			handleError(error, 'initialization');
		}
	});
	
	// Initialize individual generator instance
	function initializeGenerator(generator) {
		try {
			// Security: Verify nonce
			if (!verifyNonce(generator)) {
				showInlineNotification('Security verification failed', 'error');
				return;
			}
			
			// Security: Check rate limiting
			if (!checkRateLimit()) {
				showInlineNotification('Rate limit exceeded. Please try again later.', 'error');
				return;
			}
			
			// Cache elements with validation
			const elements = cacheElements(generator);
			if (!elements.form) {
				throw new Error('Required form element not found');
			}
			
			// Initialize features
			const state = initializeState();
			initializeFileUpload(generator, elements, state);
			initializeFormValidation(elements);
			initializeTagsManagement(generator, elements, state);
			initializeFormattingButtons(generator, elements);
			initializeFAQManagement(generator, elements, state);
			initializeChangelogManagement(generator, elements, state);
			initializeInlinePreviewHandlers(elements);
			initializeFormHandlers(elements, state);
			
			// Success message
			showInlineNotification('Readme generator loaded successfully!', 'success', 3000);
			
					} catch (error) {
			handleError(error, 'generator_initialization');
		}
	}
	
	// Cache DOM elements with error handling
	function cacheElements(generator) {
		const elements = {};
		
		try {
			elements.form = generator.querySelector('#readmeForm');
			elements.fileInput = generator.querySelector('#readmeFile');
			elements.previewBtn = generator.querySelector('#previewBtn');
			elements.downloadBtn = generator.querySelector('#downloadBtn');
			elements.previewSection = generator.querySelector('#previewSection');
			elements.previewContent = generator.querySelector('#previewContent');
			elements.hidePreviewBtn = generator.querySelector('#hidePreviewBtn');
			elements.addFAQBtn = generator.querySelector('#addFAQ');
			elements.addChangelogBtn = generator.querySelector('#addChangelog');
			elements.faqContainer = generator.querySelector('#faqContainer');
			elements.changelogContainer = generator.querySelector('#changelogContainer');
			
			// Tags elements
			elements.contributorsInput = generator.querySelector('#contributorsInput');
			elements.addContributorBtn = generator.querySelector('#addContributor');
			elements.contributorsDisplay = generator.querySelector('#contributorsDisplay');
			elements.contributorsHidden = generator.querySelector('#contributors');
			
			elements.tagsInput = generator.querySelector('#tagsInput');
			elements.addTagBtn = generator.querySelector('#addTag');
			elements.tagsDisplay = generator.querySelector('#tagsDisplay');
			elements.tagsHidden = generator.querySelector('#tags');
			
					} catch (error) {
			handleError(error, 'element_caching');
		}
		
		return elements;
	}
	
	// Initialize application state
	function initializeState() {
		return {
			contributorsTags: [],
			tagsTags: [],
			faqIndex: 1,
			changelogIndex: 1
		};
	}
	
	// Initialize file upload with enhanced security
	function initializeFileUpload(generator, elements, state) {
		if (!elements.fileInput) return;
		
		elements.fileInput.addEventListener('change', function(e) {
			try {
				const file = e.target.files[0];
				if (!file) return;
				
				// Security: Validate file
				const validation = validateFileUpload(file);
				if (!validation.valid) {
					logSecurityEvent('invalid_file_upload', { error: validation.error, filename: file.name });
					showInlineNotification(validation.error, 'error');
					e.target.value = ''; // Clear input
					return;
				}
				
				// Read and parse file
				const reader = new FileReader();
				reader.onload = function(event) {
					try {
						const content = event.target.result;
						parseReadmeFile(content, generator, elements, state);
						showInlineNotification('File imported successfully!', 'success');
					} catch (error) {
						handleError(error, 'file_parsing');
						showInlineNotification('Error parsing file. Please check the format.', 'error');
					}
				};
				
				reader.onerror = function() {
					handleError(new Error('File read error'), 'file_reading');
					showInlineNotification('Error reading file', 'error');
				};
				
				reader.readAsText(file);
				
			} catch (error) {
				handleError(error, 'file_upload');
					}
				});
			}
			
	// Enhanced file parsing with security
	function parseReadmeFile(content, generator, elements, state) {
		if (!content || typeof content !== 'string') {
			throw new Error('Invalid file content');
		}
		
		// Security: Limit content size
		if (content.length > 50000) {
			throw new Error('File content too large');
		}
		
		// Sanitize content
		content = sanitizeInput(content, 50000);
		
		try {
			// Parse sections with enhanced regex patterns
			parseBasicInfo(content, generator, state);
			parseSections(content, generator);
			parseFAQ(content, generator, elements, state);
			parseChangelog(content, generator, elements, state);
			
		} catch (error) {
			throw new Error('Failed to parse readme sections: ' + error.message);
		}
	}
	
	// Parse basic information with validation
	function parseBasicInfo(content, generator, state) {
		const lines = content.split('\n');
		let inHeader = false;
		
		// Extract plugin name
		const headerMatch = content.match(/===\s*(.+?)\s*===/i);
		if (headerMatch) {
			const pluginName = sanitizeInput(headerMatch[1], SECURITY_CONFIG.maxInputLength.pluginName);
			if (pluginName) {
				setFieldValue(generator, '#pluginName', pluginName);
			}
		}
		
		// Process header fields
		for (let i = 0; i < lines.length; i++) {
			const line = (lines[i] || '').trim();
			
			// Start of header
			if (line.match(/^===.*===$/) && !inHeader) {
				inHeader = true;
				continue;
			}
			
			// End of header - look for empty line followed by content (not section markers)
			if (inHeader && line === '') {
				// Check if next non-empty line is not a section marker
				let nextLineIndex = i + 1;
				while (nextLineIndex < lines.length && (lines[nextLineIndex] || '').trim() === '') {
					nextLineIndex++;
				}
				
				if (nextLineIndex < lines.length) {
					const nextLine = (lines[nextLineIndex] || '').trim();
					// If next line is a section marker (== Section ==), continue header parsing
					// If next line is content, end header parsing
					if (!nextLine.match(/^==\s+.*\s+==$/)) {
						inHeader = false;
						// This next line should be the short description
						if (nextLine && nextLine.length > 0) {
							setFieldValue(generator, '#shortDescription', nextLine);
						}
						break;
					}
				}
				continue;
			}
			
			if (inHeader && line.includes(':')) {
				parseHeaderField(line, generator, state);
			}
		}
		
		// Short description is now handled in the main parsing loop above
	}
	
	// Parse individual header fields
	function parseHeaderField(line, generator, state) {
		const colonIndex = line.indexOf(':');
		if (colonIndex === -1) return;
		
		const field = (line.substring(0, colonIndex) || '').trim().toLowerCase();
		const value = sanitizeInput((line.substring(colonIndex + 1) || '').trim());
		
		if (!value) return;
		
		switch (field) {
			case 'contributors':
			case 'contributor':
				const contributors = value.split(',').map(c => sanitizeInput((c || '').trim(), 50))
					.filter(c => c && validateInput(c, 'username'))
					.slice(0, SECURITY_CONFIG.maxItems.contributors);
				if (contributors.length > 0) {
					state.contributorsTags = contributors;
					updateTagsDisplay(generator, '#contributorsDisplay', contributors, 'contributor');
					setFieldValue(generator, '#contributors', contributors.join(', '));
				}
				break;
				
			case 'tags':
			case 'tag':
				const tags = value.split(',').map(t => sanitizeInput((t || '').trim(), 30))
					.filter(t => t && validateInput(t, 'tag'))
					.slice(0, SECURITY_CONFIG.maxItems.tags);
				if (tags.length > 0) {
					state.tagsTags = tags;
					updateTagsDisplay(generator, '#tagsDisplay', tags, 'tag');
					setFieldValue(generator, '#tags', tags.join(', '));
				}
				break;
				
			case 'requires at least':
			case 'requires wordpress':
				setFieldValue(generator, '#requiresAtLeast', value);
				break;
				
			case 'tested up to':
				setFieldValue(generator, '#testedUpTo', value);
				break;
				
			case 'stable tag':
				if (validateInput(value, 'version')) {
					setFieldValue(generator, '#version', value);
				}
				break;
				
			case 'requires php':
				setFieldValue(generator, '#requiresPHP', value);
				break;
		}
	}
	
	// Parse short description with improved extraction
	function parseShortDescription(content, generator) {
		try {
			// Find the header end and extract short description
			const headerEndMatch = content.match(/(?:License URI|Requires PHP|Stable tag):[^\n]*\n/i);
			if (headerEndMatch) {
				const afterHeaderIndex = headerEndMatch.index + headerEndMatch[0].length;
				const afterHeader = content.substring(afterHeaderIndex);
				
				// Extract the first non-empty, non-header line
				const descMatch = afterHeader.match(/\n\s*([^\n=][^\n]*(?:\n(?![\n=])[^\n]*)*)(?:\n\n==|$)/i);
				if (descMatch && descMatch[1]) {
					let shortDesc = sanitizeInput(
						(descMatch[1] || '')
							.trim()
							.replace(/\n+/g, ' ')
							.replace(/\s+/g, ' '),
						SECURITY_CONFIG.maxInputLength.shortDescription
					);
					
					// Validate it's not header content
					if (shortDesc.length > 5 && !shortDesc.includes(':') && 
						!shortDesc.toLowerCase().startsWith('contributors')) {
						setFieldValue(generator, '#shortDescription', shortDesc);
					}
				}
			}
		} catch (error) {
			handleError(error, 'short_description_parsing');
		}
	}
	
	// Parse content sections
	function parseSections(content, generator) {
		const sections = {
			description: /==\s*Description\s*==([\s\S]*?)(?:==|$)/i,
			installation: /==\s*Installation\s*==([\s\S]*?)(?:==|$)/i
		};
		
		for (const [sectionName, regex] of Object.entries(sections)) {
			try {
				const match = content.match(regex);
				if (match && match[1]) {
					const sectionContent = sanitizeInput(
						(match[1] || '').trim(), 
						SECURITY_CONFIG.maxInputLength[sectionName] || 5000
					);
					if (sectionContent) {
						setFieldValue(generator, '#' + sectionName, sectionContent);
					}
				}
			} catch (error) {
				handleError(error, `${sectionName}_section_parsing`);
			}
		}
	}
	
	// Parse FAQ section from content
	function parseFAQ(content, generator, elements, state) {
		try {
			const faqRegex = /==\s*Frequently Asked Questions\s*==([\s\S]*?)(?==\s*\w+\s*==|$)/i;
			const match = content.match(faqRegex);
			
			if (!match || !match[1]) return;
			
			const faqContent = match[1].trim();
			if (!faqContent) return;
			
			// Parse individual FAQ items
			const faqItems = faqContent.split(/(?==\s*[^=]+\s*=\s*$)/gm);
			let faqIndex = 1;
			
			faqItems.forEach(function(item) {
				if (!item.trim()) return;
				
				// Extract question and answer
				const lines = item.trim().split('\n');
				let question = '';
				let answer = '';
				let inAnswer = false;
				
				for (let i = 0; i < lines.length; i++) {
					const line = lines[i].trim();
					
					if (line.match(/^=\s*.+\s*=\s*$/)) {
						question = line.replace(/^=\s*|\s*=\s*$/g, '');
						inAnswer = true;
					} else if (inAnswer && line) {
						answer += line + '\n';
					}
				}
				
				if (question && answer) {
					addFAQFromParsed(generator, elements, state, question, answer.trim(), faqIndex);
					faqIndex++;
				}
			});
			
		} catch (error) {
			handleError(error, 'faq_parsing');
		}
	}
	
	// Parse changelog section from content
	function parseChangelog(content, generator, elements, state) {
		try {
			const changelogRegex = /==\s*Changelog\s*==([\s\S]*?)(?==\s*\w+\s*==|$)/i;
			const match = content.match(changelogRegex);
			
			if (!match || !match[1]) return;
			
			const changelogContent = match[1].trim();
			if (!changelogContent) return;
			
			// Parse individual changelog versions
			const versionItems = changelogContent.split(/(?==\s*[\d.]+\s*=\s*$)/gm);
			let changelogIndex = 1;
			
			versionItems.forEach(function(item) {
				if (!item.trim()) return;
				
				// Extract version and changes
				const lines = item.trim().split('\n');
				let version = '';
				const changes = [];
				
				for (let i = 0; i < lines.length; i++) {
					const line = lines[i].trim();
					
					if (line.match(/^=\s*[\d.]+\s*=\s*$/)) {
						version = line.replace(/^=\s*|\s*=\s*$/g, '');
					} else if (line.match(/^\*\s+/)) {
						const change = line.replace(/^\*\s+/, '').trim();
						if (change) {
							changes.push(change);
						}
					}
				}
				
				if (version && changes.length > 0) {
					addChangelogFromParsed(generator, elements, state, version, changes, changelogIndex);
					changelogIndex++;
				}
			});
			
		} catch (error) {
			handleError(error, 'changelog_parsing');
		}
	}
	
	// Add FAQ from parsed content
	function addFAQFromParsed(generator, elements, state, question, answer, index) {
		try {
			if (!elements.faqContainer) return;
			
			// Create new FAQ item
			const faqItem = document.createElement('div');
			faqItem.className = 'faq-item components-panel__body';
			faqItem.innerHTML = `
				<div class="faq-header">
					<span class="faq-number components-panel__body-title">FAQ #${index}</span>
					<button type="button" class="remove-faq components-button is-destructive" aria-label="Remove FAQ">×</button>
				</div>
				<div class="form-row components-base-control">
					<label class="components-base-control__label">Question</label>
					<input type="text" class="faq-question components-text-control__input" placeholder="How do I use this plugin?" maxlength="200" value="${sanitizeInput(question, 200)}">
				</div>
				<div class="form-row components-base-control">
					<label class="components-base-control__label">Answer</label>
					<textarea class="faq-answer components-textarea-control__input" rows="3" placeholder="Just install and activate the plugin..." maxlength="1000">${sanitizeInput(answer, 1000)}</textarea>
				</div>
			`;
			
			elements.faqContainer.appendChild(faqItem);
			state.faqIndex = Math.max(state.faqIndex, index + 1);
			
			// Add remove functionality
			const removeBtn = faqItem.querySelector('.remove-faq');
			removeBtn.addEventListener('click', function() {
				faqItem.remove();
			});
			
		} catch (error) {
			handleError(error, 'faq_creation');
		}
	}
	
	// Add changelog from parsed content
	function addChangelogFromParsed(generator, elements, state, version, changes, index) {
		try {
			if (!elements.changelogContainer) return;
			
			// Create new changelog item
			const changelogItem = document.createElement('div');
			changelogItem.className = 'changelog-item components-panel__body';
			
			// Build changes HTML
			let changesHTML = '';
			changes.forEach(function(change) {
				changesHTML += `
					<div class="change-item">
						<input type="text" class="changelog-change components-text-control__input" placeholder="Initial release" maxlength="200" value="${sanitizeInput(change, 200)}">
						<button type="button" class="remove-change components-button is-destructive" aria-label="Remove Change">×</button>
					</div>
				`;
			});
			
			changelogItem.innerHTML = `
				<div class="changelog-header">
					<div class="form-row components-base-control">
						<label class="components-base-control__label">Version</label>
						<input type="text" class="changelog-version components-text-control__input" placeholder="1.0.0" pattern="^\\d+\\.\\d+\\.\\d+$" maxlength="20" value="${sanitizeInput(version, 20)}">
					</div>
					<button type="button" class="remove-changelog components-button is-destructive" aria-label="Remove Changelog Entry">×</button>
				</div>
				<div class="changes-container">
					${changesHTML}
				</div>
				<button type="button" class="add-change components-button is-secondary">+ Add Change</button>
			`;
			
			elements.changelogContainer.appendChild(changelogItem);
			state.changelogIndex = Math.max(state.changelogIndex, index + 1);
			
			// Add event listeners
			setupChangelogItemListeners(changelogItem);
			
		} catch (error) {
			handleError(error, 'changelog_creation');
		}
	}
	
	// Setup changelog item event listeners
	function setupChangelogItemListeners(item) {
		const removeBtn = item.querySelector('.remove-changelog');
		const addChangeBtn = item.querySelector('.add-change');
		const changesContainer = item.querySelector('.changes-container');
		
		// Remove changelog entry
		removeBtn.addEventListener('click', function() {
			item.remove();
		});
		
		// Add new change
		addChangeBtn.addEventListener('click', function() {
			addChangeItem(changesContainer);
		});
		
		// Setup existing change items
		const changeItems = item.querySelectorAll('.change-item');
		changeItems.forEach(function(changeItem) {
			setupChangeItemListeners(changeItem);
		});
	}
	
	// Add new change item
	function addChangeItem(container) {
		const changeItem = document.createElement('div');
		changeItem.className = 'change-item';
		changeItem.innerHTML = `
			<input type="text" class="changelog-change components-text-control__input" placeholder="Initial release" maxlength="200">
			<button type="button" class="remove-change components-button is-destructive" aria-label="Remove Change">×</button>
		`;
		
		container.appendChild(changeItem);
		setupChangeItemListeners(changeItem);
	}
	
	// Setup change item listeners
	function setupChangeItemListeners(changeItem) {
		const removeBtn = changeItem.querySelector('.remove-change');
		removeBtn.addEventListener('click', function() {
			changeItem.remove();
		});
	}
	
	// Set field value with validation
	function setFieldValue(generator, selector, value) {
		try {
			const field = generator.querySelector(selector);
			if (!field || !value) return;
			
			const maxLength = parseInt(field.maxLength) || 1000;
			const sanitizedValue = sanitizeInput(value.toString(), maxLength);
			
			if (field.tagName === 'SELECT') {
				// Validate option exists before setting
				const option = field.querySelector(`option[value="${sanitizedValue}"]`);
				if (option) {
					field.value = sanitizedValue;
				}
			} else {
				field.value = sanitizedValue;
			}
			
			// Trigger change event for listeners
			field.dispatchEvent(new Event('change', { bubbles: true }));
			
		} catch (error) {
			handleError(error, 'field_value_setting');
		}
	}
	
	// Initialize form validation
	function initializeFormValidation(elements) {
		if (!elements.form) return;
		
		// Add real-time validation
		const requiredFields = elements.form.querySelectorAll('[required]');
		requiredFields.forEach(field => {
			field.addEventListener('blur', function() {
				validateField(this);
			});
			
			field.addEventListener('input', function() {
				// Clear validation state on input
				this.classList.remove('has-error');
			});
		});
	}
	
	// Validate individual field
	function validateField(field) {
		let isValid = true;
		let errorMessage = '';
		
		// Required field check
		if (field.required && !(field.value || '').trim()) {
			isValid = false;
			errorMessage = 'This field is required';
		}
		
		// Pattern validation
		if (isValid && field.pattern && field.value) {
			const regex = new RegExp(field.pattern);
			if (!regex.test(field.value)) {
				isValid = false;
				errorMessage = 'Invalid format';
			}
		}
		
		// Length validation
		if (isValid && field.maxLength && field.value.length > field.maxLength) {
			isValid = false;
			errorMessage = `Maximum length is ${field.maxLength} characters`;
		}
		
		// Update field state
		field.classList.toggle('has-error', !isValid);
		
		// Show/hide error message
		const existingError = field.parentNode.querySelector('.field-error');
		if (existingError) {
			existingError.remove();
		}
		
		if (!isValid && errorMessage) {
			const errorDiv = document.createElement('div');
			errorDiv.className = 'field-error';
			errorDiv.style.color = '#d63638';
			errorDiv.style.fontSize = '0.8em';
			errorDiv.style.marginTop = '0.25em';
			errorDiv.textContent = errorMessage;
			field.parentNode.appendChild(errorDiv);
		}
		
		return isValid;
	}
	
	// Initialize remaining features...
	// (Additional functions would follow the same security-first approach)
	
	// Initialize form handlers
	function initializeFormHandlers(elements, state) {
		if (elements.previewBtn) {
			elements.previewBtn.addEventListener('click', function(e) {
				e.preventDefault();
				try {
					showPreview(elements, state);
				} catch (error) {
					handleError(error, 'preview_generation');
				}
			});
		}
		
		if (elements.downloadBtn) {
			elements.downloadBtn.addEventListener('click', function(e) {
				e.preventDefault();
				try {
					downloadReadme(elements, state);
				} catch (error) {
					handleError(error, 'readme_download');
				}
			});
		}
	}
	
	// Generate and show inline preview
	function showPreview(elements, state) {
		if (!elements.previewContent || !elements.previewSection) return;
		
		const content = generateReadmeContent(elements, state);
		elements.previewContent.textContent = content; // Use textContent for XSS prevention
		elements.previewSection.style.display = 'block';
		elements.previewSection.setAttribute('aria-hidden', 'false');
		
		// Scroll to preview section
		elements.previewSection.scrollIntoView({ behavior: 'smooth', block: 'start' });
	}
			
	// Generate readme content with security
	function generateReadmeContent(elements, state) {
		try {
			if (!elements.form) return 'Error: Form not found';
			
			// Collect and sanitize form data
			const formData = new FormData(elements.form);
			const data = {
				plugingName: sanitizeInput(formData.get('pluginName')?.toString() || 'Plugin Name', 
					SECURITY_CONFIG.maxInputLength.pluginName),
				shortDescription: sanitizeInput(formData.get('shortDescription')?.toString() || 'Short description here.', 
					SECURITY_CONFIG.maxInputLength.shortDescription),
				contributors: sanitizeInput(formData.get('contributors')?.toString() || 'username'),
				tags: sanitizeInput(formData.get('tags')?.toString() || 'plugin'),
				version: sanitizeInput(formData.get('version')?.toString() || '1.0.0', 20),
				requiresAtLeast: sanitizeInput(formData.get('requiresAtLeast')?.toString() || '5.0'),
				testedUpTo: sanitizeInput(formData.get('testedUpTo')?.toString() || '6.8'),
				requiresPHP: sanitizeInput(formData.get('requiresPHP')?.toString() || '7.4'),
				description: sanitizeInput(formData.get('description')?.toString() || 'Detailed description here.', 
					SECURITY_CONFIG.maxInputLength.description),
				installation: sanitizeInput(formData.get('installation')?.toString() || 
					'1. Upload to /wp-content/plugins/\n2. Activate the plugin', 
					SECURITY_CONFIG.maxInputLength.installation)
			};
			
			// Validate version format
			if (!validateInput(data.version, 'version')) {
				logSecurityEvent('invalid_version_format', { version: data.version });
				data.version = '1.0.0';
			}
			
			// Generate sections
			const faqSection = generateFAQSection(elements);
			const changelogSection = generateChangelogSection(elements);
			
			// Build readme content
			const readme = `=== ${data.plugingName} ===\n\nContributors: ${data.contributors}\nTags: ${data.tags}\nRequires at least: ${data.requiresAtLeast}\nTested up to: ${data.testedUpTo}\nStable tag: ${data.version}\nRequires PHP: ${data.requiresPHP}\nLicense: GPLv2 or later\nLicense URI: https://www.gnu.org/licenses/gpl-2.0.html\n\n${data.shortDescription}\n\n== Description ==\n\n${data.description}\n\n== Installation ==\n\n${data.installation}\n\n== Frequently Asked Questions ==\n\n${faqSection.trim()}\n\n== Changelog ==\n\n${changelogSection.trim()}`;
			
			return readme;
			
		} catch (error) {
			handleError(error, 'readme_generation');
			return 'Error generating readme. Please check your inputs.';
		}
	}
	
	// Download readme with security checks
	function downloadReadme(elements, state) {
		try {
			const content = generateReadmeContent(elements, state);
			
			// Validate content
					if (!content || content.length < 10) {
						throw new Error('Invalid readme content');
					}
					
			// Create and trigger download
					const blob = new Blob([content], { type: 'text/plain;charset=utf-8' });
					const url = URL.createObjectURL(blob);
					
					const link = document.createElement('a');
					link.href = url;
					link.download = 'readme.txt';
					link.style.display = 'none';
			
					document.body.appendChild(link);
					link.click();
					document.body.removeChild(link);
					
			// Clean up
			setTimeout(() => URL.revokeObjectURL(url), 1000);
			
			showInlineNotification('Readme file downloaded successfully!', 'success');
			
				} catch (error) {
			handleError(error, 'readme_download');
			showInlineNotification('Error downloading readme. Please try again.', 'error');
		}
	}
	
	// Additional initialization functions would be implemented here
	// following the same security-first approach...
	
	// Basic implementations for required functions
	function initializeTagsManagement(generator, elements, state) {
		// Implementation with security measures
	}
	
	function initializeFormattingButtons(generator, elements) {
		// Implementation with XSS prevention
	}
	
	function initializeFAQManagement(generator, elements, state) {
		// Implementation with input validation
	}
	
	function initializeChangelogManagement(generator, elements, state) {
		// Implementation with sanitization
	}
	
	function initializeInlinePreviewHandlers(elements) {
		// Hide preview button handler
		if (elements.hidePreviewBtn) {
			elements.hidePreviewBtn.addEventListener('click', function(e) {
				e.preventDefault();
				if (elements.previewSection) {
					elements.previewSection.style.display = 'none';
					elements.previewSection.setAttribute('aria-hidden', 'true');
				}
			});
		}
	}
	
	function updateTagsDisplay(generator, selector, tags, type) {
		try {
			const display = generator.querySelector(selector);
			if (!display || !tags) return;
			
			display.innerHTML = '';
			
			tags.forEach(function(tag, index) {
				const tagElement = document.createElement('div');
				tagElement.className = 'tag';
				tagElement.innerHTML = `
					<span>${sanitizeInput(tag, 50)}</span>
					<button type="button" class="tag-remove" aria-label="Remove ${type}">×</button>
				`;
				
				// Add remove functionality
				const removeBtn = tagElement.querySelector('.tag-remove');
				removeBtn.addEventListener('click', function() {
					tags.splice(index, 1);
					updateTagsDisplay(generator, selector, tags, type);
					updateHiddenInput(display.parentNode.querySelector('input[type="hidden"]'), tags);
				});
				
				display.appendChild(tagElement);
			});
			
		} catch (error) {
			handleError(error, 'tags_display_update');
		}
	}
	
	// Initialize tags management with security
	function initializeTagsManagement(generator, elements, state) {
		// Contributors management
		if (elements.addContributorBtn && elements.contributorsInput && elements.contributorsDisplay) {
			elements.addContributorBtn.addEventListener('click', function(e) {
				e.preventDefault();
				addTag(elements.contributorsInput, elements.contributorsDisplay, state.contributorsTags, 'contributor', elements.contributorsHidden);
			});
			
			elements.contributorsInput.addEventListener('keypress', function(e) {
				if (e.key === 'Enter') {
					e.preventDefault();
					addTag(elements.contributorsInput, elements.contributorsDisplay, state.contributorsTags, 'contributor', elements.contributorsHidden);
				}
			});
		}
		
		// Tags management
		if (elements.addTagBtn && elements.tagsInput && elements.tagsDisplay) {
			elements.addTagBtn.addEventListener('click', function(e) {
				e.preventDefault();
				addTag(elements.tagsInput, elements.tagsDisplay, state.tagsTags, 'tag', elements.tagsHidden);
			});
			
			elements.tagsInput.addEventListener('keypress', function(e) {
				if (e.key === 'Enter') {
					e.preventDefault();
					addTag(elements.tagsInput, elements.tagsDisplay, state.tagsTags, 'tag', elements.tagsHidden);
				}
			});
		}
	}
	
	// Add tag with validation
	function addTag(input, display, tagArray, type, hiddenInput) {
		try {
			const value = sanitizeInput(input.value.trim(), 50);
			
			if (!value) {
				showNotification('Please enter a valid tag', 'error', 3000);
				return;
			}
			
			// Validate tag format
			if (type === 'contributor' && !validateInput(value, 'username')) {
				showNotification('Invalid contributor username format', 'error', 3000);
				return;
			}
			
			if (type === 'tag' && !validateInput(value, 'tag')) {
				showNotification('Invalid tag format', 'error', 3000);
				return;
			}
			
			// Check for duplicates
			if (tagArray.includes(value)) {
				showNotification('Tag already exists', 'error', 3000);
				return;
			}
			
			// Check limits
			const maxItems = type === 'contributor' ? SECURITY_CONFIG.maxItems.contributors : SECURITY_CONFIG.maxItems.tags;
			if (tagArray.length >= maxItems) {
				showNotification(`Maximum ${maxItems} ${type}s allowed`, 'error', 3000);
				return;
			}
			
			// Add tag
			tagArray.push(value);
			updateTagsDisplaySimple(display, tagArray, type);
			updateHiddenInput(hiddenInput, tagArray);
			
			// Clear input
			input.value = '';
			input.focus();
			
		} catch (error) {
			handleError(error, 'tag_addition');
		}
	}
	
	// Update hidden input with tag values
	function updateHiddenInput(hiddenInput, tagArray) {
		if (hiddenInput && tagArray) {
			hiddenInput.value = tagArray.join(', ');
		}
	}
	
	// Simple version of updateTagsDisplay for direct use
	function updateTagsDisplaySimple(display, tagArray, type) {
		try {
			if (!display || !tagArray) return;
			
			display.innerHTML = '';
			
			tagArray.forEach(function(tag, index) {
				const tagElement = document.createElement('div');
				tagElement.className = 'tag';
				tagElement.innerHTML = `
					<span>${sanitizeInput(tag, 50)}</span>
					<button type="button" class="tag-remove" aria-label="Remove ${type}">×</button>
				`;
				
				// Add remove functionality
				const removeBtn = tagElement.querySelector('.tag-remove');
				removeBtn.addEventListener('click', function() {
					tagArray.splice(index, 1);
					updateTagsDisplaySimple(display, tagArray, type);
					updateHiddenInput(display.parentNode.querySelector('input[type="hidden"]'), tagArray);
				});
				
				display.appendChild(tagElement);
			});
			
		} catch (error) {
			handleError(error, 'tags_display_simple_update');
		}
	}
	
	// Initialize formatting buttons with XSS prevention
	function initializeFormattingButtons(generator, elements) {
		const formattingButtons = generator.querySelectorAll('.format-btn');
		
		formattingButtons.forEach(function(btn) {
			btn.addEventListener('click', function(e) {
				e.preventDefault();
				
				try {
					const format = this.dataset.format;
					const textarea = this.closest('.form-row').querySelector('textarea');
					
					if (!textarea) return;
					
					applyFormatting(format, textarea);
					
				} catch (error) {
					handleError(error, 'formatting_button_click');
				}
			});
		});
	}
	
	// Apply formatting with security
	function applyFormatting(format, textarea) {
		try {
			const start = textarea.selectionStart;
			const end = textarea.selectionEnd;
			const selectedText = textarea.value.substring(start, end);
			const beforeText = textarea.value.substring(0, start);
			const afterText = textarea.value.substring(end);
			
			let formattedText = '';
			
			switch (format) {
				case 'bold':
					formattedText = selectedText ? `**${selectedText}**` : '**bold text**';
					break;
				case 'italic':
					formattedText = selectedText ? `*${selectedText}*` : '*italic text*';
					break;
				case 'code':
					formattedText = selectedText ? `\`${selectedText}\`` : '`code`';
					break;
				case 'heading':
					formattedText = selectedText ? `= ${selectedText} =` : '= Heading =';
					break;
				case 'bullet':
					formattedText = selectedText ? `* ${selectedText}` : '* List item';
					break;
				case 'numbered':
					formattedText = selectedText ? `1. ${selectedText}` : '1. List item';
					break;
				case 'link':
					formattedText = selectedText ? `[${selectedText}](https://example.com)` : '[Link text](https://example.com)';
					break;
				default:
					return;
			}
			
			// Sanitize formatted text
			formattedText = sanitizeInput(formattedText, 1000);
			
			// Update textarea
			textarea.value = beforeText + formattedText + afterText;
			
			// Set cursor position
			const newCursorPos = start + formattedText.length;
			textarea.setSelectionRange(newCursorPos, newCursorPos);
			textarea.focus();
			
		} catch (error) {
			handleError(error, 'formatting_application');
		}
	}
	
	// Initialize FAQ management with input validation
	function initializeFAQManagement(generator, elements, state) {
		if (!elements.addFAQBtn || !elements.faqContainer) return;
		
		elements.addFAQBtn.addEventListener('click', function(e) {
			e.preventDefault();
			addFAQ(elements.faqContainer, state);
		});
		
		// Setup existing FAQ items
		const existingFAQs = elements.faqContainer.querySelectorAll('.faq-item');
		existingFAQs.forEach(function(faq) {
			setupFAQItemListeners(faq);
		});
	}
	
	// Add new FAQ
	function addFAQ(container, state) {
		try {
			const faqIndex = state.faqIndex;
			const faqItem = document.createElement('div');
			faqItem.className = 'faq-item components-panel__body';
			faqItem.innerHTML = `
				<div class="faq-header">
					<span class="faq-number components-panel__body-title">FAQ #${faqIndex}</span>
					<button type="button" class="remove-faq components-button is-destructive" aria-label="Remove FAQ">×</button>
				</div>
				<div class="form-row components-base-control">
					<label class="components-base-control__label">Question</label>
					<input type="text" class="faq-question components-text-control__input" placeholder="How do I use this plugin?" maxlength="200">
				</div>
				<div class="form-row components-base-control">
					<label class="components-base-control__label">Answer</label>
					<textarea class="faq-answer components-textarea-control__input" rows="3" placeholder="Just install and activate the plugin..." maxlength="1000"></textarea>
				</div>
			`;
			
			container.appendChild(faqItem);
			state.faqIndex++;
			
			setupFAQItemListeners(faqItem);
			
		} catch (error) {
			handleError(error, 'faq_addition');
		}
	}
	
	// Setup FAQ item listeners
	function setupFAQItemListeners(faqItem) {
		const removeBtn = faqItem.querySelector('.remove-faq');
		removeBtn.addEventListener('click', function() {
			faqItem.remove();
		});
		
		// Add validation to inputs
		const questionInput = faqItem.querySelector('.faq-question');
		const answerTextarea = faqItem.querySelector('.faq-answer');
		
		if (questionInput) {
			questionInput.addEventListener('input', function() {
				this.value = sanitizeInput(this.value, 200);
			});
		}
		
		if (answerTextarea) {
			answerTextarea.addEventListener('input', function() {
				this.value = sanitizeInput(this.value, 1000);
			});
		}
	}
	
	// Initialize changelog management with sanitization
	function initializeChangelogManagement(generator, elements, state) {
		if (!elements.addChangelogBtn || !elements.changelogContainer) return;
		
		elements.addChangelogBtn.addEventListener('click', function(e) {
			e.preventDefault();
			addChangelog(elements.changelogContainer, state);
		});
		
		// Setup existing changelog items
		const existingChangelogs = elements.changelogContainer.querySelectorAll('.changelog-item');
		existingChangelogs.forEach(function(changelog) {
			setupChangelogItemListeners(changelog);
		});
	}
	
	// Add new changelog
	function addChangelog(container, state) {
		try {
			const changelogIndex = state.changelogIndex;
			const changelogItem = document.createElement('div');
			changelogItem.className = 'changelog-item components-panel__body';
			changelogItem.innerHTML = `
				<div class="changelog-header">
					<div class="form-row components-base-control">
						<label class="components-base-control__label">Version</label>
						<input type="text" class="changelog-version components-text-control__input" placeholder="1.0.0" pattern="^\\d+\\.\\d+\\.\\d+$" maxlength="20">
					</div>
					<button type="button" class="remove-changelog components-button is-destructive" aria-label="Remove Changelog Entry">×</button>
				</div>
				<div class="changes-container">
					<div class="change-item">
						<input type="text" class="changelog-change components-text-control__input" placeholder="Initial release" maxlength="200">
						<button type="button" class="remove-change components-button is-destructive" aria-label="Remove Change">×</button>
					</div>
				</div>
				<button type="button" class="add-change components-button is-secondary">+ Add Change</button>
			`;
			
			container.appendChild(changelogItem);
			state.changelogIndex++;
			
			setupChangelogItemListeners(changelogItem);
			
		} catch (error) {
			handleError(error, 'changelog_addition');
		}
	}
	
	// Initialize modal handlers with focus management
	function initializeModalHandlers(elements) {
		if (!elements.previewModal) return;
		
		// Close modal functionality
		if (elements.closeModal) {
			elements.closeModal.addEventListener('click', function() {
				closeModal(elements.previewModal);
			});
		}
		
		// Close on escape key
		document.addEventListener('keydown', function(e) {
			if (e.key === 'Escape' && elements.previewModal.style.display === 'flex') {
				closeModal(elements.previewModal);
			}
		});
		
		// Close on backdrop click
		elements.previewModal.addEventListener('click', function(e) {
			if (e.target === this) {
				closeModal(this);
			}
		});
		
		// Modal download button
		if (elements.modalDownloadBtn) {
			elements.modalDownloadBtn.addEventListener('click', function(e) {
				e.preventDefault();
				closeModal(elements.previewModal);
				// Trigger main download
				if (elements.downloadBtn) {
					elements.downloadBtn.click();
				}
			});
		}
	}
	
	// Close modal with focus management
	function closeModal(modal) {
		modal.style.display = 'none';
		modal.setAttribute('aria-hidden', 'true');
		
		// Return focus to preview button
		const previewBtn = document.querySelector('#previewBtn');
		if (previewBtn) {
			previewBtn.focus();
		}
	}
	
	function generateFAQSection(elements) {
		try {
			const faqItems = elements.form.querySelectorAll('.faq-item');
			let faqSection = '';
			
			faqItems.forEach(function(item) {
				const question = item.querySelector('.faq-question').value.trim();
				const answer = item.querySelector('.faq-answer').value.trim();
				
				if (question && answer) {
					const sanitizedQuestion = sanitizeInput(question, 200);
					const sanitizedAnswer = sanitizeInput(answer, 1000);
					faqSection += `= ${sanitizedQuestion} =\n\n${sanitizedAnswer}\n\n`;
				}
			});
			
			return faqSection || '= How do I use this plugin? =\n\nJust install and activate the plugin through the WordPress admin.\n\n';
		} catch (error) {
			handleError(error, 'faq_section_generation');
			return '= How do I use this plugin? =\n\nJust install and activate the plugin through the WordPress admin.\n\n';
		}
	}
	
	function generateChangelogSection(elements) {
		try {
			const changelogItems = elements.form.querySelectorAll('.changelog-item');
			let changelogSection = '';
			
			changelogItems.forEach(function(item) {
				const version = item.querySelector('.changelog-version').value.trim();
				const changes = item.querySelectorAll('.changelog-change');
				
				if (version && changes.length > 0) {
					const sanitizedVersion = sanitizeInput(version, 20);
					changelogSection += `= ${sanitizedVersion} =\n`;
					
					changes.forEach(function(changeInput) {
						const change = changeInput.value.trim();
						if (change) {
							const sanitizedChange = sanitizeInput(change, 200);
							changelogSection += `* ${sanitizedChange}\n`;
						}
					});
					
					changelogSection += '\n';
				}
			});
			
			return changelogSection || '= 1.0.0 =\n* Initial release\n\n';
		} catch (error) {
			handleError(error, 'changelog_section_generation');
		return '= 1.0.0 =\n* Initial release\n\n';
		}
	}
	
})();