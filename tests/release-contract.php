<?php
/**
 * Portable release contract for LUNARA AI Assistant Classic.
 * Run: php tests/release-contract.php
 */

$root = dirname( __DIR__ );
$plugin = file_get_contents( $root . DIRECTORY_SEPARATOR . 'lunara-ai-assistant-classic.php' );
$failures = array();

if ( false === $plugin ) {
	fwrite( STDERR, "Could not read release files.\n" );
	exit( 1 );
}

$required = array(
	"'x-goog-api-key' => \$api_key" => 'Gemini key is not sent in the request header',
	"':generateContent'" => 'Gemini Generate Content endpoint is missing',
);
foreach ( $required as $needle => $message ) {
	if ( false === strpos( $plugin, $needle ) ) {
		$failures[] = $message;
	}
}

if ( false !== strpos( $plugin, ':generateContent?key=' ) ) {
	$failures[] = 'Gemini key remains in the request URL';
}

// The version lives in one file and is never pinned here: the header and the
// runtime constant must agree.
if ( ! preg_match( '/^[ \t\/*#@]*Version:\s*(\S+)\s*$/m', $plugin, $header_version )
	|| ! preg_match( "/define\(\s*'LUNARA_AI_ASSISTANT_CLASSIC_VERSION',\s*'([^']+)'\s*\)/", $plugin, $runtime_version ) ) {
	$failures[] = 'plugin header or runtime version is missing';
} elseif ( $header_version[1] !== $runtime_version[1] ) {
	$failures[] = 'plugin header version ' . $header_version[1] . ' does not match runtime version ' . $runtime_version[1];
}

if ( $failures ) {
	fwrite( STDERR, "AI Assistant release contract failed:\n- " . implode( "\n- ", $failures ) . "\n" );
	exit( 1 );
}

echo "AI Assistant release contract passed.\n";
