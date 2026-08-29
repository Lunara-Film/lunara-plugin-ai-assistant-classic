<?php
/**
 * Runtime contract for the redacted Site Studio integration API.
 * Run: php tests/site-studio-status-contract.php
 */

$scenario = getenv( 'LUNARA_AI_STATUS_SCENARIO' );

if ( false === $scenario || '' === $scenario ) {
	$scenarios = array(
		'denied',
		'capability-throws',
		'capability-absent',
		'authorized-then-denied',
		'ready-redacted',
		'auto-priority-filter-isolation',
		'malicious-settings',
		'model-grammar',
		'surface-bounds',
		'classic-surface-filter-compatibility',
		'constant-whitespace-shadow',
		'constant-precedence',
		'env-whitespace-shadow',
		'gemini-env-whitespace-shadow',
		'google-env-fallback',
		'unsafe-admin-url',
		'uniform-filter-admin-url',
		'subdirectory-admin-url',
		'extra-query-admin-url',
		'unsafe-admin-paths',
		'throwing-admin-url',
		'missing-option-helper',
		'throwing-option-helper',
		'missing-post-type-helpers',
	);
	$failures  = array();

	foreach ( $scenarios as $child_scenario ) {
		$environment                                = getenv();
		$environment['LUNARA_AI_STATUS_SCENARIO']   = $child_scenario;
		$environment['OPENAI_API_KEY']              = '';
		$environment['ANTHROPIC_API_KEY']           = '';
		$environment['GEMINI_API_KEY']              = '';
		$environment['GOOGLE_API_KEY']              = '';
		$descriptors                                = array(
			0 => array( 'pipe', 'r' ),
			1 => array( 'pipe', 'w' ),
			2 => array( 'pipe', 'w' ),
		);
		$process                                    = proc_open( array( PHP_BINARY, __FILE__ ), $descriptors, $pipes, dirname( __DIR__ ), $environment );

		if ( ! is_resource( $process ) ) {
			$failures[] = $child_scenario . ': could not start isolated PHP process';
			continue;
		}

		fclose( $pipes[0] );
		$stdout = stream_get_contents( $pipes[1] );
		$stderr = stream_get_contents( $pipes[2] );
		fclose( $pipes[1] );
		fclose( $pipes[2] );
		$exit_code = proc_close( $process );

		if ( 0 !== $exit_code ) {
			$failures[] = $child_scenario . ': ' . trim( $stderr . "\n" . $stdout );
		}
	}

	if ( $failures ) {
		fwrite( STDERR, "Site Studio status contract failed:\n- " . implode( "\n- ", $failures ) . "\n" );
		exit( 1 );
	}

	echo "Site Studio status contract passed (" . count( $scenarios ) . " isolated scenarios).\n";
	exit( 0 );
}

$GLOBALS['lunara_test'] = array(
	'allowed'          => true,
	'capability_calls' => array(),
	'option_calls'     => 0,
	'filter_calls'     => 0,
	'filter_arguments' => array(),
	'url_calls'        => 0,
	'http_calls'       => 0,
	'mutation_calls'   => 0,
	'settings'         => array(),
	'post_types'       => array(
		'post'    => true,
		'journal' => true,
		'review'  => true,
	),
	'url_mode'         => 'safe',
);

function lunara_test_fail( $message ) {
	fwrite( STDERR, $message . "\n" );
	exit( 1 );
}

function lunara_test_assert_same( $expected, $actual, $message ) {
	if ( $expected !== $actual ) {
		lunara_test_fail(
			$message . "\nExpected: " . var_export( $expected, true ) . "\nActual: " . var_export( $actual, true )
		);
	}
}

function lunara_test_assert_true( $value, $message ) {
	if ( true !== $value ) {
		lunara_test_fail( $message );
	}
}

function lunara_test_assert_not_contains( $needle, $haystack, $message ) {
	if ( false !== strpos( $haystack, $needle ) ) {
		lunara_test_fail( $message . ': leaked ' . $needle );
	}
}

function plugin_dir_path( $file ) {
	return dirname( $file ) . DIRECTORY_SEPARATOR;
}

function plugin_dir_url( $file ) {
	return 'https://example.test/wp-content/plugins/lunara-ai-assistant-classic/';
}

function add_action() {
	return null;
}

function wp_parse_args( $args, $defaults = array() ) {
	return array_merge( $defaults, is_array( $args ) ? $args : array() );
}

function sanitize_key( $key ) {
	$key = strtolower( (string) $key );
	return preg_replace( '/[^a-z0-9_\-]/', '', $key );
}

if ( ! in_array( $scenario, array( 'capability-absent' ), true ) ) {
	function current_user_can( $capability ) {
		$GLOBALS['lunara_test']['capability_calls'][] = $capability;
		if ( 'capability-throws' === getenv( 'LUNARA_AI_STATUS_SCENARIO' ) ) {
			throw new RuntimeException( 'capability secret must not escape' );
		}
		return $GLOBALS['lunara_test']['allowed'];
	}
}

if ( ! in_array( $scenario, array( 'missing-option-helper' ), true ) ) {
	function get_option( $key, $default = false ) {
		$GLOBALS['lunara_test']['option_calls']++;
		if ( 'throwing-option-helper' === getenv( 'LUNARA_AI_STATUS_SCENARIO' ) ) {
			throw new RuntimeException( 'option secret must not escape' );
		}
		return $GLOBALS['lunara_test']['settings'];
	}
}

if ( ! in_array( $scenario, array( 'missing-post-type-helpers' ), true ) ) {
	function post_type_exists( $post_type ) {
		return isset( $GLOBALS['lunara_test']['post_types'][ $post_type ] );
	}

	function post_type_supports( $post_type, $feature ) {
		return 'editor' === $feature && ! empty( $GLOBALS['lunara_test']['post_types'][ $post_type ] );
	}
}

function apply_filters( $hook, $value ) {
	$GLOBALS['lunara_test']['filter_calls']++;
	$GLOBALS['lunara_test']['filter_arguments'][] = array( $hook, $value );
	if ( 'classic-surface-filter-compatibility' === getenv( 'LUNARA_AI_STATUS_SCENARIO' ) ) {
		return array_merge( $value, array( 'contributed_surface' ) );
	}
	throw new RuntimeException( 'hostile surface filter ran' );
}

function admin_url( $path = '' ) {
	$GLOBALS['lunara_test']['url_calls']++;
	if ( 'throw' === $GLOBALS['lunara_test']['url_mode'] ) {
		throw new RuntimeException( 'URL secret must not escape' );
	}
	if ( '' === $path ) {
		if ( 'uniform-cross-origin' === $GLOBALS['lunara_test']['url_mode'] ) {
			return 'https://attacker.example/wp-admin/';
		}
		if ( 'uniform-double-slash-path' === $GLOBALS['lunara_test']['url_mode'] ) {
			return 'https://example.test/subdir//wp-admin/';
		}
		if ( 'subdirectory' === $GLOBALS['lunara_test']['url_mode'] ) {
			return 'https://mapped.example:8443/wordpress/wp-admin/';
		}
		return 'https://example.test/wp-admin/';
	}
	if ( 'uniform-cross-origin' === $GLOBALS['lunara_test']['url_mode'] ) {
		return 'https://attacker.example/wp-admin/' . $path;
	}
	if ( 'uniform-double-slash-path' === $GLOBALS['lunara_test']['url_mode'] ) {
		return 'https://example.test/subdir//wp-admin/' . $path;
	}
	if ( 'subdirectory' === $GLOBALS['lunara_test']['url_mode'] ) {
		return 'https://mapped.example:8443/wordpress/wp-admin/' . $path;
	}
	if ( 'cross-origin' === $GLOBALS['lunara_test']['url_mode'] ) {
		return 'https://attacker.example/wp-admin/' . $path;
	}
	if ( 'extra-query' === $GLOBALS['lunara_test']['url_mode'] ) {
		return 'https://example.test/wp-admin/' . $path . '&secret=1';
	}
	if ( 'fragment' === $GLOBALS['lunara_test']['url_mode'] ) {
		return 'https://example.test/wp-admin/' . $path . '#secret';
	}
	if ( 'userinfo' === $GLOBALS['lunara_test']['url_mode'] ) {
		return 'https://user:pass@example.test/wp-admin/' . $path;
	}
	if ( 'encoded-path' === $GLOBALS['lunara_test']['url_mode'] ) {
		return 'https://example.test/wp-admin/%6fptions-general.php?page=lunara-ai-assistant-classic';
	}
	if ( 'encoded-control' === $GLOBALS['lunara_test']['url_mode'] ) {
		return 'https://example.test/wp-admin/options-general.php?page=lunara-ai-assistant-classic%0A';
	}
	if ( 'raw-control' === $GLOBALS['lunara_test']['url_mode'] ) {
		return "https://example.test/wp-admin/options-general.php?page=lunara-ai-assistant-classic\n";
	}
	if ( 'backslash' === $GLOBALS['lunara_test']['url_mode'] ) {
		return 'https://example.test/wp-admin\\options-general.php?page=lunara-ai-assistant-classic';
	}
	if ( 'dot-segment' === $GLOBALS['lunara_test']['url_mode'] ) {
		return 'https://example.test/wp-admin/child/../options-general.php?page=lunara-ai-assistant-classic';
	}
	if ( 'scheme-relative' === $GLOBALS['lunara_test']['url_mode'] ) {
		return '//example.test/wp-admin/' . $path;
	}
	if ( 'malformed' === $GLOBALS['lunara_test']['url_mode'] ) {
		return 'http://[invalid';
	}
	return 'https://example.test/wp-admin/' . $path;
}

function wp_remote_post() {
	$GLOBALS['lunara_test']['http_calls']++;
	throw new RuntimeException( 'provider request must not run' );
}

function update_option() {
	$GLOBALS['lunara_test']['mutation_calls']++;
	throw new RuntimeException( 'option mutation must not run' );
}

function add_option() {
	$GLOBALS['lunara_test']['mutation_calls']++;
	throw new RuntimeException( 'option mutation must not run' );
}

function delete_option() {
	$GLOBALS['lunara_test']['mutation_calls']++;
	throw new RuntimeException( 'option mutation must not run' );
}

if ( 'constant-whitespace-shadow' === $scenario ) {
	define( 'LUNARA_OPENAI_API_KEY', '   ' );
	putenv( 'OPENAI_API_KEY=env-openai-secret' );
} elseif ( 'constant-precedence' === $scenario ) {
	define( 'LUNARA_OPENAI_API_KEY', 'constant-openai-secret' );
	putenv( 'OPENAI_API_KEY=   ' );
} elseif ( 'env-whitespace-shadow' === $scenario ) {
	putenv( 'ANTHROPIC_API_KEY=   ' );
} elseif ( 'gemini-env-whitespace-shadow' === $scenario ) {
	putenv( 'GEMINI_API_KEY=   ' );
	putenv( 'GOOGLE_API_KEY=google-secret' );
} elseif ( 'google-env-fallback' === $scenario ) {
	putenv( 'GOOGLE_API_KEY=google-secret' );
}

define( 'ABSPATH', dirname( __DIR__ ) . DIRECTORY_SEPARATOR );
require dirname( __DIR__ ) . DIRECTORY_SEPARATOR . 'lunara-ai-assistant-classic.php';

$denied = array(
	'state'      => 'unavailable',
	'label'      => 'AI Assistant unavailable',
	'message'    => 'AI Assistant status is unavailable.',
	'updated_at' => '',
	'url'        => '',
	'capability' => 'manage_options',
);

if ( in_array( $scenario, array( 'denied', 'capability-throws', 'capability-absent' ), true ) ) {
	$GLOBALS['lunara_test']['allowed'] = false;
	$status = lunara_ai_assistant_classic_site_studio_status();
	lunara_test_assert_same( $denied, $status, 'denied status must be the fixed minimal envelope' );
	lunara_test_assert_same( 0, $GLOBALS['lunara_test']['option_calls'], 'denial must precede option access' );
	lunara_test_assert_same( 0, $GLOBALS['lunara_test']['filter_calls'], 'denial must precede filter access' );
	lunara_test_assert_same( 0, $GLOBALS['lunara_test']['url_calls'], 'denial must precede URL access' );
	lunara_test_assert_same( '', lunara_ai_assistant_classic_settings_url(), 'denied settings URL must be empty' );
	exit( 0 );
}

if ( 'authorized-then-denied' === $scenario ) {
	$GLOBALS['lunara_test']['settings'] = array(
		'provider'          => 'openai',
		'api_key'           => 'saved-openai-secret',
		'model'             => 'gpt-4o',
		'post_types'        => 'post',
		'system_prompt'     => 'prompt-secret',
	);
	$authorized = lunara_ai_assistant_classic_site_studio_status();
	lunara_test_assert_same( 'openai', $authorized['provider'], 'authorized setup must expose the recognized provider' );
	$reads_before_denial                    = $GLOBALS['lunara_test'];
	$GLOBALS['lunara_test']['allowed']      = false;
	$denied_after_authorized                = lunara_ai_assistant_classic_site_studio_status();
	lunara_test_assert_same( $denied, $denied_after_authorized, 'denial after authorization must not reuse detailed status' );
	lunara_test_assert_same( $reads_before_denial['option_calls'], $GLOBALS['lunara_test']['option_calls'], 'denied repeat must not read options' );
	lunara_test_assert_same( $reads_before_denial['filter_calls'], $GLOBALS['lunara_test']['filter_calls'], 'denied repeat must not run filters' );
	lunara_test_assert_same( $reads_before_denial['url_calls'], $GLOBALS['lunara_test']['url_calls'], 'denied repeat must not build URLs' );
	exit( 0 );
}

if ( 'ready-redacted' === $scenario ) {
	$secret_prompt = 'PROMPT-ULTRA-PRIVATE-7eab';
	$secret_key    = 'sk-private-openai-9f21';
	$GLOBALS['lunara_test']['settings'] = array(
		'provider'          => 'openai',
		'api_key'           => $secret_key,
		'model'             => 'gpt-4o-mini',
		'anthropic_api_key' => '',
		'gemini_api_key'    => '',
		'post_types'        => 'post,review,bad slug,review',
		'system_prompt'     => $secret_prompt,
		'request_history'   => 'HISTORY-SECRET-192a',
	);
	$before = $GLOBALS['lunara_test']['settings'];
	$status = lunara_ai_assistant_classic_site_studio_status();
	$expected = array(
		'state'            => 'ready',
		'label'            => 'AI Assistant ready',
		'message'          => 'AI Assistant configuration is ready for editorial use.',
		'updated_at'       => '',
		'provider'         => 'openai',
		'provider_label'   => 'OpenAI',
		'model'            => 'gpt-4o-mini',
		'enabled_surfaces' => array( 'post', 'review' ),
		'key_presence'     => array(
			'openai'    => true,
			'anthropic' => false,
			'gemini'    => false,
		),
		'url'              => '/wp-admin/options-general.php?page=lunara-ai-assistant-classic',
		'capability'       => 'manage_options',
	);
	lunara_test_assert_same( $expected, $status, 'authorized DTO keys, types, labels, and values must be exact' );
	lunara_test_assert_same( array( 'manage_options' ), $GLOBALS['lunara_test']['capability_calls'], 'status must check only manage_options' );
	lunara_test_assert_same( 1, $GLOBALS['lunara_test']['option_calls'], 'status must read the combined option exactly once' );
	lunara_test_assert_same( 0, $GLOBALS['lunara_test']['filter_calls'], 'status must bypass contributed surface filters' );
	lunara_test_assert_same( 0, $GLOBALS['lunara_test']['http_calls'], 'status must not make a provider request' );
	lunara_test_assert_same( 0, $GLOBALS['lunara_test']['mutation_calls'], 'status must not mutate options' );
	lunara_test_assert_same( $before, $GLOBALS['lunara_test']['settings'], 'status must leave the credential-bearing option byte-for-byte equivalent in memory' );
	$json = json_encode( $status );
	foreach ( array( $secret_key, $secret_prompt, 'HISTORY-SECRET-192a', 'sk-private', 'PROMPT-ULTRA' ) as $fragment ) {
		lunara_test_assert_not_contains( $fragment, $json, 'serialized DTO must redact secrets, prompts, history, and fragments' );
	}
	lunara_test_assert_same( $expected['url'], lunara_ai_assistant_classic_settings_url(), 'settings URL helper must return the canonical authorized URL' );
	exit( 0 );
}

if ( 'auto-priority-filter-isolation' === $scenario ) {
	$GLOBALS['lunara_test']['settings'] = array(
		'provider'          => 'unknown-provider',
		'api_key'           => 'openai-secret',
		'model'             => 'gpt-4o',
		'anthropic_api_key' => 'anthropic-secret',
		'anthropic_model'   => 'claude-sonnet-4',
		'gemini_api_key'    => 'gemini-secret',
		'gemini_model'      => 'gemini-2.0-flash',
		'post_types'        => 'post',
	);
	$status = lunara_ai_assistant_classic_site_studio_status();
	lunara_test_assert_same( 'anthropic', $status['provider'], 'invalid provider must behave as auto with Anthropic priority' );
	lunara_test_assert_same( 'Anthropic (Claude)', $status['provider_label'], 'provider label must come from the fixed map' );
	lunara_test_assert_same( 0, $GLOBALS['lunara_test']['filter_calls'], 'hostile filters must remain uncalled' );
	exit( 0 );
}

if ( 'malicious-settings' === $scenario ) {
	$throwing_object = new class() {
		public function __toString() {
			throw new RuntimeException( 'object secret must not be cast' );
		}
	};
	$GLOBALS['lunara_test']['settings'] = array(
		'provider'          => $throwing_object,
		'api_key'           => array( 'OPENAI-ARRAY-SECRET' ),
		'model'             => $throwing_object,
		'anthropic_api_key' => $throwing_object,
		'anthropic_model'   => array( 'claude-secret' ),
		'gemini_api_key'    => array( 'GEMINI-ARRAY-SECRET' ),
		'gemini_model'      => $throwing_object,
		'post_types'        => $throwing_object,
		'system_prompt'     => $throwing_object,
	);
	$status = lunara_ai_assistant_classic_site_studio_status();
	lunara_test_assert_same( 'anthropic', $status['provider'], 'malformed provider must resolve through automatic fallback' );
	lunara_test_assert_same( '', $status['model'], 'malformed model must be rejected rather than cast or sanitized' );
	lunara_test_assert_same( array(), $status['enabled_surfaces'], 'malformed surfaces must be rejected rather than cast' );
	lunara_test_assert_same( array( 'openai' => false, 'anthropic' => false, 'gemini' => false ), $status['key_presence'], 'malformed credentials must produce fixed false booleans' );
	$json = json_encode( $status );
	foreach ( array( 'OPENAI-ARRAY-SECRET', 'claude-secret', 'GEMINI-ARRAY-SECRET' ) as $secret ) {
		lunara_test_assert_not_contains( $secret, $json, 'malformed settings must remain redacted' );
	}
	exit( 0 );
}

if ( 'model-grammar' === $scenario ) {
	$cases = array(
		array( 'openai', 'model', 'gpt-4o', 'gpt-4o' ),
		array( 'openai', 'model', 'o3-mini', 'o3-mini' ),
		array( 'openai', 'model', 'gpt-', '' ),
		array( 'openai', 'model', 'o0-preview', '' ),
		array( 'openai', 'model', ' gpt-4o ', '' ),
		array( 'openai', 'model', "gpt-4o secret\nkey", '' ),
		array( 'openai', 'model', 'gpt-' . str_repeat( 'a', 77 ), '' ),
		array( 'anthropic', 'anthropic_model', 'claude-sonnet-4', 'claude-sonnet-4' ),
		array( 'anthropic', 'anthropic_model', 'claude secret', '' ),
		array( 'gemini', 'gemini_model', 'models/gemini-2.0-flash', 'gemini-2.0-flash' ),
		array( 'gemini', 'gemini_model', ' models/gemini-2.0-flash', '' ),
		array( 'gemini', 'gemini_model', 'models/models/gemini-secret', '' ),
	);
	foreach ( $cases as $case ) {
		$GLOBALS['lunara_test']['settings'] = array(
			'provider'          => $case[0],
			'api_key'           => 'key',
			'model'             => 'gpt-4o',
			'anthropic_api_key' => 'key',
			'anthropic_model'   => 'claude-sonnet-4',
			'gemini_api_key'    => 'key',
			'gemini_model'      => 'gemini-2.0-flash',
			'post_types'        => 'post',
		);
		$GLOBALS['lunara_test']['settings'][ $case[1] ] = $case[2];
		$status = lunara_ai_assistant_classic_site_studio_status();
		lunara_test_assert_same( $case[3], $status['model'], 'model grammar mismatch for ' . $case[0] . ' / ' . $case[2] );
	}
	exit( 0 );
}

if ( 'surface-bounds' === $scenario ) {
	$valid = array();
	for ( $i = 0; $i < 18; $i++ ) {
		$slug = 'surface_' . $i;
		$valid[] = $slug;
		$GLOBALS['lunara_test']['post_types'][ $slug ] = true;
	}
	$GLOBALS['lunara_test']['post_types']['twenty_char_slug_123'] = true;
	$GLOBALS['lunara_test']['settings'] = array(
		'provider'   => 'openai',
		'api_key'    => 'key',
		'model'      => 'gpt-4o',
		'post_types' => implode( ',', array_merge( array( 'Bad Slug', 'post<script>', 'surface_0' ), $valid ) ),
	);
	$status = lunara_ai_assistant_classic_site_studio_status();
	lunara_test_assert_same( array_slice( $valid, 0, 16 ), $status['enabled_surfaces'], 'surfaces must be strict, unique, registered, editor-supported, and capped at 16' );
	exit( 0 );
}

if ( 'classic-surface-filter-compatibility' === $scenario ) {
	$GLOBALS['lunara_test']['post_types']['badslug']   = true;
	$GLOBALS['lunara_test']['post_types']['no_editor'] = false;
	$GLOBALS['lunara_test']['settings'] = array(
		'post_types' => ' Post ,review,review,missing,no_editor,bad slug',
	);
	$enabled = Lunara_AI_Assistant_Classic::get_enabled_post_types();
	lunara_test_assert_same(
		array( 'post', 'review', 'badslug', 'contributed_surface' ),
		$enabled,
		'Classic Editor surfaces must retain the contributed filter output'
	);
	lunara_test_assert_same( 1, $GLOBALS['lunara_test']['filter_calls'], 'Classic Editor surface resolver must invoke its filter exactly once' );
	lunara_test_assert_same(
		array(
			array(
				'lunara_ai_assistant_classic_post_types',
				array( 'post', 'review', 'badslug' ),
			),
		),
		$GLOBALS['lunara_test']['filter_arguments'],
		'Classic Editor filter must receive sanitized, unique, registered, editor-supported surfaces'
	);
	exit( 0 );
}

if ( in_array( $scenario, array( 'constant-whitespace-shadow', 'constant-precedence', 'env-whitespace-shadow', 'gemini-env-whitespace-shadow', 'google-env-fallback' ), true ) ) {
	$GLOBALS['lunara_test']['settings'] = array(
		'provider'          => 'auto',
		'api_key'           => 'saved-openai-secret',
		'model'             => 'gpt-4o',
		'anthropic_api_key' => 'saved-anthropic-secret',
		'anthropic_model'   => 'claude-sonnet-4',
		'gemini_api_key'    => 'saved-gemini-secret',
		'gemini_model'      => 'gemini-2.0-flash',
		'post_types'        => 'post',
	);
	$status = lunara_ai_assistant_classic_site_studio_status();
	if ( 'constant-whitespace-shadow' === $scenario ) {
		lunara_test_assert_same( false, $status['key_presence']['openai'], 'truthy whitespace constant must shadow env and saved key' );
	} elseif ( 'constant-precedence' === $scenario ) {
		lunara_test_assert_same( true, $status['key_presence']['openai'], 'non-empty constant must take precedence over env and saved key' );
	} elseif ( 'env-whitespace-shadow' === $scenario ) {
		lunara_test_assert_same( false, $status['key_presence']['anthropic'], 'truthy whitespace environment value must shadow saved key' );
	} elseif ( 'gemini-env-whitespace-shadow' === $scenario ) {
		lunara_test_assert_same( false, $status['key_presence']['gemini'], 'truthy whitespace GEMINI_API_KEY must shadow GOOGLE_API_KEY and saved key' );
	} else {
		lunara_test_assert_same( true, $status['key_presence']['gemini'], 'GOOGLE_API_KEY must remain the final Gemini environment fallback' );
	}
	exit( 0 );
}

if ( in_array( $scenario, array( 'unsafe-admin-url', 'uniform-filter-admin-url', 'subdirectory-admin-url', 'extra-query-admin-url', 'unsafe-admin-paths', 'throwing-admin-url' ), true ) ) {
	if ( 'unsafe-admin-url' === $scenario ) {
		$GLOBALS['lunara_test']['url_mode'] = 'cross-origin';
	} elseif ( 'uniform-filter-admin-url' === $scenario ) {
		$GLOBALS['lunara_test']['url_mode'] = 'uniform-cross-origin';
	} elseif ( 'subdirectory-admin-url' === $scenario ) {
		$GLOBALS['lunara_test']['url_mode'] = 'subdirectory';
	} elseif ( 'extra-query-admin-url' === $scenario ) {
		$GLOBALS['lunara_test']['url_mode'] = 'extra-query';
	} else {
		$GLOBALS['lunara_test']['url_mode'] = 'throwing-admin-url' === $scenario ? 'throw' : 'safe';
	}
	$GLOBALS['lunara_test']['settings'] = array(
		'provider' => 'openai', 'api_key' => 'key', 'model' => 'gpt-4o', 'post_types' => 'post',
	);
	$status = lunara_ai_assistant_classic_site_studio_status();
	if ( in_array( $scenario, array( 'unsafe-admin-url', 'uniform-filter-admin-url' ), true ) ) {
		lunara_test_assert_same( '/wp-admin/options-general.php?page=lunara-ai-assistant-classic', $status['url'], 'uniform foreign filtering must be stripped to the safe root-relative admin destination' );
		lunara_test_assert_not_contains( 'attacker.example', json_encode( $status ), 'uniform foreign filtering must never survive in status output' );
		lunara_test_assert_same( 'ready', $status['state'], 'valid root-relative admin destination may retain configuration readiness' );
		exit( 0 );
	}
	if ( 'subdirectory-admin-url' === $scenario ) {
		lunara_test_assert_same( '/wordpress/wp-admin/options-general.php?page=lunara-ai-assistant-classic', $status['url'], 'legitimate subdirectory admin paths must be preserved root-relative' );
		lunara_test_assert_same( 'ready', $status['state'], 'legitimate subdirectory admin paths may retain configuration readiness' );
		exit( 0 );
	}
	if ( 'unsafe-admin-paths' === $scenario ) {
		foreach ( array( 'fragment', 'userinfo', 'encoded-path', 'encoded-control', 'raw-control', 'backslash', 'dot-segment', 'uniform-double-slash-path', 'scheme-relative', 'malformed' ) as $url_mode ) {
			$GLOBALS['lunara_test']['url_mode'] = $url_mode;
			$status = lunara_ai_assistant_classic_site_studio_status();
			lunara_test_assert_same( '', $status['url'], 'unsafe admin URL mode must return an empty destination: ' . $url_mode );
			lunara_test_assert_same( 'unavailable', $status['state'], 'unsafe admin URL mode must make status unavailable: ' . $url_mode );
		}
		exit( 0 );
	}
	lunara_test_assert_same( '', $status['url'], 'unsafe or throwing admin URL must degrade to an empty URL' );
	lunara_test_assert_same( 'unavailable', $status['state'], 'unsafe or throwing URL facility must make status unavailable' );
	exit( 0 );
}

if ( in_array( $scenario, array( 'missing-option-helper', 'throwing-option-helper', 'missing-post-type-helpers' ), true ) ) {
	$GLOBALS['lunara_test']['settings'] = array(
		'provider' => 'openai', 'api_key' => 'key', 'model' => 'gpt-4o', 'post_types' => 'post',
	);
	$status = lunara_ai_assistant_classic_site_studio_status();
	lunara_test_assert_same( 'unavailable', $status['state'], 'missing or throwing WordPress facility must make status unavailable' );
	lunara_test_assert_same(
		array( 'state', 'label', 'message', 'updated_at', 'provider', 'provider_label', 'model', 'enabled_surfaces', 'key_presence', 'url', 'capability' ),
		array_keys( $status ),
		'authorized unavailable status must retain the exact detailed DTO shape'
	);
	lunara_test_assert_same( 0, $GLOBALS['lunara_test']['http_calls'], 'degraded status must not call a provider' );
	lunara_test_assert_same( 0, $GLOBALS['lunara_test']['mutation_calls'], 'degraded status must not mutate state' );
	exit( 0 );
}

lunara_test_fail( 'Unknown test scenario: ' . $scenario );
