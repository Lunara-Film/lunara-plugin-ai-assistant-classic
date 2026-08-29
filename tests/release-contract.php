<?php
/**
 * Portable release contract for LUNARA AI Assistant Classic.
 * Run: php tests/release-contract.php
 */

$root = dirname( __DIR__ );
$plugin = file_get_contents( $root . DIRECTORY_SEPARATOR . 'lunara-ai-assistant-classic.php' );
$readme = file_get_contents( $root . DIRECTORY_SEPARATOR . 'README.md' );
$wordpress_readme = file_get_contents( $root . DIRECTORY_SEPARATOR . 'readme.txt' );
$workflow = file_get_contents( $root . DIRECTORY_SEPARATOR . '.github' . DIRECTORY_SEPARATOR . 'workflows' . DIRECTORY_SEPARATOR . 'lint.yml' );
$failures = array();

if ( false === $plugin || false === $readme || false === $wordpress_readme || false === $workflow ) {
	fwrite( STDERR, "Could not read release files.\n" );
	exit( 1 );
}

$required = array(
	'Version:           0.6.2' => 'plugin header is not 0.6.2',
	"LUNARA_AI_ASSISTANT_CLASSIC_VERSION', '0.6.2'" => 'runtime version is not 0.6.2',
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
if ( false === strpos( $readme, 'Current baseline: `0.6.2`.' ) ) {
	$failures[] = 'README baseline is not 0.6.2';
}
if ( false === strpos( $wordpress_readme, 'Stable tag: 0.6.2' ) ) {
	$failures[] = 'WordPress stable tag is not 0.6.2';
}
if ( false === strpos( $wordpress_readme, '= 0.6.2 =' ) ) {
	$failures[] = 'WordPress changelog is missing 0.6.2';
}
if ( false === strpos( $workflow, "php-version: ['7.4', '8.2']" ) ) {
	$failures[] = 'CI workflow does not enforce PHP 7.4 and 8.2';
}
if ( false === strpos( $workflow, 'php tests/site-studio-status-contract.php' ) ) {
	$failures[] = 'CI workflow does not run the Site Studio status contract';
}

if ( $failures ) {
	fwrite( STDERR, "AI Assistant release contract failed:\n- " . implode( "\n- ", $failures ) . "\n" );
	exit( 1 );
}

echo "AI Assistant release contract passed.\n";
