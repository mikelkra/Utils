<?php 

if (! defined("GRANT_ACCESS"))
	die();

/**
 * costumeHeaders($_method)
 * cleanData($data)
 * BBQ()
 */
class Utils {
	
	private $request_method;
	
	public function customHeaders($_method){
		$this->request_method = $_method;
		header ( "Access-Control-Allow-Origin: <your domain>" );
		header ( "Access-Control-Allow-Headers: Authorization" );
		header ( "Access-Control-Allow-Methods:" .$this->request_method  );
		header ( "Access-Control-Allow-Credentials: true" );
		header ( 'Content-Type: application/json' );
		header ( "X-XSS-Protection: 1; mode=block" );
		header ( "X-Content-Type-Options: nosniff" );
		header ( "Strict-Transport-Security: max-age=31536000" );
		header ( "Content-Security-Policy: default-src 'none'; script-src 'self'; connect-src 'self'; img-src 'self'; style-src 'self';" );
	}
	
	// clean user inputs
	public function cleanData($data) {
		if (is_array ( $data )) {
			// if array
			$cleanData = array_map ( 'cleanData', $data );
		} else {
			
			if (filter_var ( $data, FILTER_VALIDATE_EMAIL )) {
				// if EMAIL
				$cleanData = filter_var ( $data, FILTER_SANITIZE_EMAIL );
			} elseif (filter_var ( $data, FILTER_VALIDATE_URL )) {
				// if URL
				$cleanData = filter_var ( $data, FILTER_SANITIZE_URL );
			} else {
				// if anything else (string, ip ...)
				$cleanData = filter_var ( $data, FILTER_SANITIZE_STRIPPED );
				$cleanData = filter_var ( $cleanData, FILTER_SANITIZE_STRING );
				$cleanData = filter_var ( $cleanData, FILTER_SANITIZE_SPECIAL_CHARS );
				$cleanData = trim ( $cleanData ); 
				$cleanData = strip_tags ( $cleanData ); 
			}
		}
		return $cleanData;
	}
	
	// block bad queries
  // from BBQ site
	public function BBQ(){

		$request_uri = $_SERVER['REQUEST_URI'];
		$query_string = $_SERVER['QUERY_STRING'];
		$user_agent = $_SERVER['HTTP_USER_AGENT'];
		
		// request uri
		if (	//strlen($request_uri) > 255 ||
				stripos($request_uri, 'eval(') ||
				stripos($request_uri, 'CONCAT') ||
				stripos($request_uri, 'UNION+SELECT') ||
				stripos($request_uri, '(null)') ||
				stripos($request_uri, 'base64_') ||
				stripos($request_uri, '/localhost') ||
				stripos($request_uri, '/pingserver') ||
				stripos($request_uri, '/config.') ||
				stripos($request_uri, '/wwwroot') ||
				stripos($request_uri, '/makefile') ||
				stripos($request_uri, 'crossdomain.') ||
				stripos($request_uri, 'proc/self/environ') ||
				stripos($request_uri, 'etc/passwd') ||
				stripos($request_uri, '/https/') ||
				stripos($request_uri, '/http/') ||
				stripos($request_uri, '/ftp/') ||
				stripos($request_uri, '/cgi/') ||
				stripos($request_uri, '.cgi') ||
				stripos($request_uri, '.exe') ||
				stripos($request_uri, '.sql') ||
				stripos($request_uri, '.ini') ||
				stripos($request_uri, '.dll') ||
				stripos($request_uri, '.asp') ||
				stripos($request_uri, '.jsp') ||
				stripos($request_uri, '/.bash') ||
				stripos($request_uri, '/.git') ||
				stripos($request_uri, '/.svn') ||
				stripos($request_uri, '/.tar') ||
				stripos($request_uri, ' ') ||
				stripos($request_uri, '<') ||
				stripos($request_uri, '>') ||
				stripos($request_uri, '/=') ||
				stripos($request_uri, '...') ||
				stripos($request_uri, '+++') ||
				stripos($request_uri, '://') ||
				stripos($request_uri, '/&&') ||
				// query strings
				stripos($query_string, '?') ||
				stripos($query_string, ':') ||
				stripos($query_string, '[') ||
				stripos($query_string, ']') ||
				stripos($query_string, '../') ||
				stripos($query_string, '127.0.0.1') ||
				stripos($query_string, 'loopback') ||
				stripos($query_string, '%0A') ||
				stripos($query_string, '%0D') ||
				stripos($query_string, '%22') ||
				stripos($query_string, '%27') ||
				stripos($query_string, '%3C') ||
				stripos($query_string, '%3E') ||
				stripos($query_string, '%00') ||
				stripos($query_string, '%2e%2e') ||
				stripos($query_string, 'union') ||
				stripos($query_string, 'input_file') ||
				stripos($query_string, 'execute') ||
				stripos($query_string, 'mosconfig') ||
				stripos($query_string, 'environ') ||
				//stripos($query_string, 'scanner') ||
				stripos($query_string, 'path=.') ||
				stripos($query_string, 'mod=.') ||
				// user agents
				stripos($user_agent, 'binlar') ||
				stripos($user_agent, 'casper') ||
				stripos($user_agent, 'cmswor') ||
				stripos($user_agent, 'diavol') ||
				stripos($user_agent, 'dotbot') ||
				stripos($user_agent, 'finder') ||
				stripos($user_agent, 'flicky') ||
				stripos($user_agent, 'libwww') ||
				stripos($user_agent, 'nutch') ||
				stripos($user_agent, 'planet') ||
				stripos($user_agent, 'purebot') ||
				stripos($user_agent, 'pycurl') ||
				stripos($user_agent, 'skygrid') ||
				stripos($user_agent, 'sucker') ||
				stripos($user_agent, 'turnit') ||
				stripos($user_agent, 'vikspi') ||
				stripos($user_agent, 'zmeu')
				) {
					@header('HTTP/1.1 403 Forbidden');
					@header('Status: 403 Forbidden');
					@header('Connection: Close');
					@exit;
				}
	}
}



?>
