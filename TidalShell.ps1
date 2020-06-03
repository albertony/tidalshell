#
# TidalShell
#

#
# Developer notes:
# - API is available at api.tidalhifi.com, currently in version 1
#   so base url: https://api.tidalhifi.com/v1/
# - Before any other requests can be made, one must perform a login by sending
#   a POST-request to the API path /login/username. The request must include
#   your Tidal credentials (username and password) in the body, as well as
#   an API token in a "X-Tidal-Token" header (or by a "token" query parameter).
#   More notes about the token below.
# - A successful login request will return your internal user id, a
#   country code, and most importantly: a unique session id (GUID).
#   All following requests must include the session id, either in the query
#   part of the URL or as a "X-Tidal-SessionId" header.
# - Authentication:
#     - To be able to access the API one must first perform a login,
#       which gives us a session id to be used on following requests (more below).
#     - One can use login using credentials, a personal TIDAL username and password,
#       or one can login use token based authentication.
#     - After an initial login using credentials one can retrieve the authentication
#       token by sending a request to users/<userid>/loginToken.
#     - In the login methods of this script we always fetch the authentication token
#       and keeps it as a script (session) variable so that subsequent logins
#       can be done without user input. For safety we encrypt the token using
#       "Windows Data Protection API" (DPAPI), which means that it will only
#       work for the same user on the same computer.
# - API/application token:
#     - As well as a TIDAL username and password, the Tidal API needs an API
#       token.
#     - You can get this token by network-sniffing (by use of Fiddler for
#       example) some application that uses TIDAL Playback feature, like Tidal
#       for Windows, Tidal for Android, or CapTune from Sennheiser. Also
#       the Web UI at listen.tidal.com sends a token.
#     - TODO: Not sure if this is which is unique to each apps?
#       It seems we can "borrow" tokens from others, but it seems to be tied 
#       to the subscription level so that a token for a lossless subscription
#       cannot be used together with the username of an account without
#       lossless subscription.
#     - The following tokens are hard coded into a Python module available
#       at http://pythonhosted.org/tidalapi/_modules/tidalapi.html, and I
#       see the same tokens are used from the Web UI (listen.tidal.com)
#       on my computer:
#         - If lossless subscription: P5Xbeo5LFvESeDy6
#         - Else, normal subscription:wdgaB1CilGA-S_s2
#       And the following is from github.com/datagutt/WiMP-api:
#         P5Xbeo5LFvESeDy6
# - Entity tag:
#     - Modifications of playlists are using optimistic concurrency control
#       based on the HTTP ETag header: The Get request returns an identifier
#       (probably a timestamp) in a header "Etag" of its response, and then to
#       be allowed modifying the playlist this identifier must be supplied in
#       a header "If-None-Match" of the next Post request. The server will
#       compare the identifier received and only allow the modification if
#       they match, which means that the playlist have not been modified since
#       the ETag was sent to the client.
# - Session id:
#     - A unique id in the form of a GUID that you get from a successful login.
#     - All following requests must include the session id, either in the query
#       part of the URL or as a "X-Tidal-SessionId" header.
# - Country code:
#     - The user is tied to a region via countryCode property,
#       retrieved from /users/<userid>.
#     - The countryCode property of the user is also included in the session
#       properties returned from the logon request.
#     - Most requests require countryCode to be specified as parameter,
#       this includes requests for playlists, artists, tracks etc.
#         - Although the Web GUI seems to always supply the country code in\
#           the query-part of the url, then for post-requests it can instead
#           be part of the content.
#         - TODO: Think this is requests related to region-specific information,
#                 artists and tracks etc can probably be available only in
#                 specific regions.
#         - TODO: Not sure if a countryCode value different than the user/session
#                 can be specified in individual requests?
# - List returns:
#     - For requests returning list of items, the results are "paginated"
#       so that a limited number of items are returned. The limit can be
#       specified by parameter "limit", default seems to be 10.
#       The response content from such requests includes the property
#       "totalNumberOfItems" that tells us if there are more items remaining.
#       To get more items one must specify additional parameter "offset".
#     - This script has implemented a wrapper function for these requests
#       that repeats the request with offset according to limit until all
#       items are retrieved, resulting in an unpaginated list of items.
# - Streaming and quality
#     - One can get an url for streaming tracks via /tracks/<trackId>/streamUrl
#       request.
#     - The URL is only valid for a period of time, it seems it includes the
#       expiration timestamp in a query parameter "Expires" where the value
#       is a Unix time (seconds since 1 January 1970).
#     - The streaming request takes a parameter 'soundQuality' that can
#       be set to one of: 'LOSSLESS', 'HIGH' and 'LOW' (and probably the new 'MASTER'?)
#     - The High and Low qualities requires Tidal Premium subscription, and the
#       two lossless qualities (lossless and master) requires Tidal HiFi subscription.
#     - The audio quality:
#          - Master uses lossless 24 bit 96 kHz (88-192 kHz) MQA in FLAC (Android/Windows) or ALAC (iOS/macOS) container.
#          - Lossless (also called Hi-Fi) uses lossless 16bit 44.1kHz FLAC (Android/Windows) or ALAC (iOS/macOS) with a bitrate of 1411Kbps.
#          - High uses MPEG AAC Audio in a mp4a container with a bitrate of 320Kbps.
#          - Low (also called Standard) uses MPEG AAC+ Audio in a mp4a container with a bitrate of 96Kbps.
#
# - TODO:
#   - Still some confusion around playlists: built-in vs user playlists,
#     and playlists vs. featured/promotions/rising/moods etc...?
#   - Client version:
#       - The official Web UI also includes clientVersion (as of 01.11.2017 with value "2.4.4--5") in the login requests..
#
# Sources
#   Other unofficial Tidal API wrappers:
#     https://github.com/lucaslg26/TidalAPI
#     https://github.com/datagutt/WiMP-api
#     http://pythonhosted.org/tidalapi/_modules/tidalapi.html
#   Spotify's WebAPI, which is similar in structure:
#     https://developer.spotify.com/web-api/

# Script configuration constants:
$TidalApiBaseUrl = 'https://api.tidalhifi.com/v1'
$TidalToken = 'wdgaB1CilGA-S_s2'

# Script variables:
<#
# Session: This information is the result of a successful login and contains the session identifier used on subsequent API requests.
$TidalSession = @{
	$userId = '12345678'
	$sessionId = 'a93ba24a-6b8d-4423-b51c-53e04a26c12d'
	$countryCode = 'NO'
}

# Authentication token: Fetched after a successful login, and not cleared after logout so that it can be used for subsequent logins!
# NB: It is kept encrypted using "Windows Data Protection API" (DPAPI), which means that it will only work for the same user on the same computer.
$TidalAuthenticationTokenEncrypted = '01000000d08c9ddf0115d1118c7a00c04fc297eb010000000129b9b49dd23a4fb90166169b371b440000000002000000000003660000c00000001000000063dff7eed0e224c8783ff05adaff65b50000000004800000a0000000100000009e3490642b998fdafc2ed59bea9200bb2800000077f0ec3745680e18e393537cf839479e31e37f03f18feccd65e7138f7984008b88ed3402efffdfbc14000000c90a01935dc69b900a06159c29514c98a083c2bc'
# Can be decrypted locally like this: (New-Object System.Management.Automation.PSCredential("N\A", (ConvertTo-SecureString $TidalAuthenticationTokenEncrypted))).GetNetworkCredential().Password
# resulting in a string looking like this 'MadfAfdskAl215Adfd43Afds6JmfdswWdfsOXsefwqA24fds'

# Subscription: Subscription details, fetched after a successful login, but not strictly necessary.
$TidalSubscription = @{
	validUntil          : 2017-11-29T23:59:59.564+0000
	status              : ACTIVE
	subscription        : @{type=PREMIUM; offlineGracePeriod=30}
	highestSoundQuality : HIGH
	premiumAccess       : True
	canGetTrial         : True
	paymentType         : EXTERNAL_CONTRACT_NO_VALIDATION
}
#>

function Tidal-GetAllItems($Function, $ArgumentList, $Limit)
{
	# Generic wrapper for calling a named function to fetch paginated items
	# according to a specified limit repeatedly until all items are retrieved.
	# NB: The function variable will be executed with the call operator (&),
	# so it can in principle be a cmdlet, function, script block, script file,
	# or operable program. But we assume it takes arguments -Limit and -Offset,
	# and returns an object with properties limit, totalNumberOfItems and 
	# and items collection. So it is intended for any of our Tidal functions
	# returning items, such as Tidal-GetUserPlaylists.
	$result = &$Function @ArgumentList -Limit $Limit
	if ($result -and $result.totalNumberOfItems -gt 0) {
		$index = 0
		while ($index -lt $result.totalNumberOfItems) {
			if ($index % $result.limit -eq 0) {
				$result = &$Function @ArgumentList -Limit $Limit -Offset $index
			}
			$result.items[$index % $result.limit]
			++$index
		}
	}
}
function Tidal-PrepareRequestParameters
{
	# Prepare a request to the Tidal REST API by creating a hashtable that can
	# be "splatted" into a call to the Invoke-RestMethod or Invoke-WebRequest
	# command. This means the hashtable keys will be "method", "headers", "body",
	# etc (casing does not matter: function call parameters are case insensitive,
	# and hashtable keys are also so).
	# Input are a REST method path which will be appended to the base URL of
	# the Tidal API and used as URL. Then there is a request method which is
	# self explanatory. Then there is a hashtable of options, which depending
	# on the request method will be either added to the URL as a query string
	# (if Get request), or specified as body (if Post request). Any headers
	# may also be specified.
	param
	(
		[string]$Path,
		[ValidateSet('Get', 'Post', 'Delete')][string]$Method = 'Get',
		[hashtable]$Options,
		[hashtable]$Headers
	)
	# For Get requests we send options as query string, for Post requests we send them in the body.
	$pathAndQuery = [uri]::EscapeUriString($Path).Replace("+", "%2B").Replace("#", "%23") # Additional escaping for '+' and '#' characters (but not sure if necessary), Uri escapes everything else for us (including %20 for space).
	if ($Method.ToLower() -eq 'post') {
		$body = $Options
	} else {
		if ($Options) {
			$pathAndQuery += "?"
			foreach ($param in $Options.GetEnumerator())
			{
				$pathAndQuery += [uri]::EscapeDataString($param.Key) + "="
				if ($param.Value -is [array]) {
					# Escape individual array items and then combine with comma ',' character (not escape the comma)
					$escapedValues = @()
					foreach($paramValue in $param.Value) {
						$escapedValues += [uri]::EscapeDataString($paramValue)
					}
					$pathAndQuery += $escapedValues -join ','
				} else {
					$pathAndQuery += [uri]::EscapeDataString($param.Value)
				}
				$pathAndQuery += "&"
			}
			$pathAndQuery = $pathAndQuery.Remove($pathAndQuery.Length - 1)
		}
	}
	@{ 'uri' = "${TidalApiBaseUrl}/${pathAndQuery}"; 'method' = $Method; 'headers' = $Headers; 'body' = $body }
}
function Tidal-InvokeRequest
{
	# Invoke basic request to the Tidal REST API
	param
	(
		[string]$Path,
		[ValidateSet('Get', 'Post', 'Delete')][string]$Method = 'Get',
		[hashtable]$Options,
		[hashtable]$Headers,
		[switch]$Session, # If request depends on session, and session id will then be automatically included as a header.
		[switch]$RegionAndSession, # If request depends on region (country code), and then implicit also session! The session id is automatically included as a header, and the country code is automatically added as an option - which will either be included in the url as a query string (if Get request) or included in the request body (if Post request).
		[switch]$WebResponse, # Default is to just get the content parsed as JSON
		[uint32]$Limit, # For requests returning paginated item lists, this limits the number of items returned. If combined with -AllItems this limits the number of items in each request.
		[uint32]$Offset, # For requests returning paginated item lists, this specifies the first item to return. Combined with -Limit this can be used to process individual "pages".
		[switch]$AllItems # For requests returning paginated item lists, this repeats the request until all items are fetched and then return the unpaginated item list. The -Limit restricts the number of items per request, effectively also the number of requests. The -Offset cannot be combined with this option, since it is being used implicit.
	)
	if ($AllItems) {
		# Use the helper function Tidal-GetAllItems to repeat the same request until all items are fetched.
		# Passing on all parameters except the three item-list related arguments.
		$recurseParameters = $PsBoundParameters
		$null = $recurseParameters.Remove('Limit')
		$null = $recurseParameters.Remove('Offset')
		$null = $recurseParameters.Remove('AllItems')
		Tidal-GetAllItems $MyInvocation.MyCommand $recurseParameters -Limit:$Limit
	} else {
		$requestHeaders = $Headers
		$requestOptions = $Options
		if ($Session -or $RegionAndSession) {
			if (-not (Tidal-HasLoggedIn)) { throw "Not logged in" }
			$requestHeaders += @{'X-Tidal-SessionId' = $TidalSession.sessionId}
			if ($RegionAndSession) {
				$requestOptions += @{'countryCode' = $TidalSession.countryCode}
			}
		}
		if ($Limit) { $requestOptions['limit'] = $Limit }
		if ($Offset) { $requestOptions['offset'] = $Offset }
		$requestParameters = Tidal-PrepareRequestParameters $Path $Method $requestOptions $requestHeaders
		#$requestParameters # Enable this for debugging
		if ($WebResponse) {
			Invoke-WebRequest @requestParameters
		} else {
			Invoke-RestMethod @requestParameters
		}
	}
}
function Tidal-CheckConnection()
{
	# Tidal API accepts request on path "ping" without having logged in, so this is just to check that the API is available.
	try
	{
		$null = Tidal-InvokeRequest 'ping'
		$true
	}
	catch
	{
		if ($_.Exception.Response) {
			Write-Warning "Error response from API request: $($_.Exception.Response.StatusDescription)"
		} else {
			Write-Warning "Error occured trying to send API request: $($_.Exception)"
		}
		$false
	}
}
function Tidal-GetCountry()
{
	# Tidal API accepts request on path "country" and responds with countryCode,
	# even without having logged in, so this probably gives us the country code
	# based on our IP address?
	try
	{
		(Tidal-InvokeRequest 'country').countryCode
	}
	catch
	{
		if ($_.Exception.Response) {
			Write-Warning "Error response from API request: $($_.Exception.Response.StatusDescription)"
		} else {
			Write-Warning "Error occured trying to send API request: $($_.Exception)"
		}
		$false
	}
}
function Tidal-LoginWithCredentials
{
	param
	(
		[Parameter(Mandatory = $false)] # Mandatory, but we want our own Get-Credential command to be run as default so we mark it as not mandatory. This means we must handle $null values later, if user cancels the dialogs etc.
		[PSCredential]$Credentials = $(Get-Credential -UserName $Username -Message "Enter your Tidal credentials") # Credentials with secure password, or $null if user cancelled.
	)
	# Perform login using on Tidal credentials (username and password),
	# which will be supplied as content of a post-request, in addition to the
	# required API/application token in header.
	# Result is a session id that we must supply for later requests regarding content tied to our account.
	# Also fetching the authentication token for the user. Keeping this in a session variable,
	# but encrypted using "Windows Data Protection API" (DPAPI), which means that it will only work for the same user on the same computer.
	# TODO: The official Web UI also includes clientVersion (as of 01.11.2017 with value "2.4.4--5") in the login request..
	if ($Credentials)
	{
		$networkCredentials = $Credentials.GetNetworkCredential()
		try
		{
			$Script:TidalSession = Tidal-InvokeRequest -Path 'login/username' -Method 'Post' -Options @{'username'=$networkCredentials.UserName;'password'=$networkCredentials.Password} -Headers @{'X-Tidal-Token'=$TidalToken}
			$Script:TidalAuthenticationTokenEncrypted = (Tidal-InvokeRequest "users/$($TidalSession.userId)/loginToken" -Session).authenticationToken | ConvertTo-SecureString -AsPlainText -Force | ConvertFrom-SecureString
			$Script:TidalSubscription = Tidal-InvokeRequest "users/$($TidalSession.userId)/subscription" -Session
		}
		catch
		{
			if ($_.Exception.Response) {
				Write-Error "Login failed due to error response from API request: $($_.Exception.Response.StatusDescription)"
			} else {
				Write-Error "Login failed due to error trying to send API request: $($_.Exception)"
			}
		}
	} else {
		Write-Error "Login failed: Credentials not specified"
	}
}
function Tidal-LoginWithToken($AuthenticationToken)
{
	# Perform login using authentication token (token based authentication),
	# which will be supplied as content of a post-request, in addition to the
	# required API/application token in header.
	# NB: Argument is optional, because after a successful login the authentication token
	# is fetched and kept as a session variable and then a later login will re-use that!
	# Result is a session id that we must supply for later requests regarding content tied to our account.
	# Also fetching the authentication token for the user. Keeping this in a session variable,
	# but encrypted using "Windows Data Protection API" (DPAPI), which means that it will only work for the same user on the same computer.
	# TODO: The official Web UI also includes clientVersion (as of 01.11.2017 with value "2.4.4--5") in the login request..
	if (!$AuthenticationToken) {
		if ($Script:TidalAuthenticationTokenEncrypted) {
			# Authentication token was not specified by caller, and we have one from a previous successful login
			# in the same client session, so we use that one!
			$AuthenticationToken = (New-Object System.Management.Automation.PSCredential("N\A", (ConvertTo-SecureString $TidalAuthenticationTokenEncrypted))).GetNetworkCredential().Password
		}
	}
	if ($AuthenticationToken) {
		try
		{
			$Script:TidalSession = Tidal-InvokeRequest -Path 'login/token' -Method 'Post' -Options @{'authenticationToken'=$AuthenticationToken} -Headers @{'X-Tidal-Token'=$TidalToken}
			$Script:TidalAuthenticationTokenEncrypted = (Tidal-InvokeRequest "users/$($TidalSession.userId)/loginToken" -Session).authenticationToken | ConvertTo-SecureString -AsPlainText -Force | ConvertFrom-SecureString
			$Script:TidalSubscription = Tidal-InvokeRequest "users/$($TidalSession.userId)/subscription" -Session
		}
		catch
		{
			if ($_.Exception.Response) {
				Write-Error "Login failed due to error response from API request: $($_.Exception.Response.StatusDescription)"
			} else {
				Write-Error "Login failed due to error trying to send API request: $($_.Exception)"
			}
		}
	} else {
		Write-Error "Login failed: Authentication token not specified"
	}
}
function Tidal-Login($AuthenticationTokenOrCredentials)
{
	# Wrapper for the two login methods: Token-based and credential-based!
	# - If either an authentication token or authentication credentials are supplied then it will be used.
	# - Else, if authentication token from a previous login is known then it will be used.
	# - Else there will be a interactive login dialog followed by login using entered credentials.
	if ($AuthenticationTokenOrCredentials) {
		if ($AuthenticationTokenOrCredentials -is [PSCredential]) {
			Tidal-LoginWithCredentials $AuthenticationTokenOrCredentials
		} else {
			Tidal-LoginWithToken $AuthenticationTokenOrCredentials
		}
	} elseif ($Script:TidalAuthenticationTokenEncrypted) {
		Tidal-LoginWithToken # No arguments, since the stored authentication token must be decrypted and will default to that within the method.
	} else {
		Tidal-LoginWithCredentials
	}
}
function Tidal-HasLoggedIn()
{
	# If logged in at least once in the current session we should have
	# a user id and session id as script variables. We do not know if
	# the session are still valid though.
	$TidalSession.userId -and $TidalSession.sessionId
}
function Tidal-CheckLogin()
{
	if (Tidal-HasLoggedIn) {
		# If we have logged in at least once, then check if the session
		# is still valid by requesting information about the user
		try
		{
			$login = Tidal-InvokeRequest "users/$($TidalSession.userId)" -Session
			if ($login) {
				if ($login.id -eq $Script:TidalSession.userId) {
					Write-Verbose "OK: Still logged as $Script:TidalSession.username (id: $($Script:TidalSession.userId))"
					$true
				} else {
					Write-Warning "Logged in, but as $login.username (id: $($login.userId)) which is different from the user of the existing session $Script:TidalSession.username (id: $($Script:TidalSession.userId))"
					$false
				}
			} else {
				Write-Warning "API request for user information did not return any result"
				$false
			}
		}
		catch
		{
			Write-Warning "API request failed: $($_.Exception.Response.StatusDescription)"
			Remove-Variable -Name TidalSession -Scope Script -ErrorAction Ignore
			#Remove-Variable -Name TidalAuthenticationTokenEncrypted -Scope Script -ErrorAction Ignore # No, do not reset this since it can be reused for later logon attempts!
			Remove-Variable -Name TidalSubscription -Scope Script -ErrorAction Ignore
			$false
		}
	} else {
		Write-Warning "Never logged in"
		Remove-Variable -Name TidalSession -Scope Script -ErrorAction Ignore
		#Remove-Variable -Name TidalAuthenticationTokenEncrypted -Scope Script -ErrorAction Ignore # No, do not reset this since it can be reused for later logon attempts!
		Remove-Variable -Name TidalSubscription -Scope Script -ErrorAction Ignore
		$false
	}
}
function Tidal-Logout()
{
	if (Tidal-HasLoggedIn) {
		try
		{
			$null = Tidal-InvokeRequest "logout" -Method 'Post' -Session
			Remove-Variable -Name TidalSession -Scope Script -ErrorAction Ignore
			#Remove-Variable -Name TidalAuthenticationTokenEncrypted -Scope Script -ErrorAction Ignore # No, do not reset this since it can be reused for later logon attempts!
			Remove-Variable -Name TidalSubscription -Scope Script -ErrorAction Ignore
		}
		catch
		{
			if ($_.Exception.Response) {
				Write-Warning "Logout failed due to error response from API request: $($_.Exception.Response.StatusDescription)"
			} else {
				Write-Warning "Logout failed due to error trying to send API request: $($_.Exception)"
			}
		}
	} else {
		Write-Warning "Never logged in"
	}
}
function Tidal-GetUser()
{
	Tidal-InvokeRequest "users/$($TidalSession.userId)" -Session
}
function Tidal-GetSubscription()
{
	Tidal-InvokeRequest "users/$($TidalSession.userId)/subscription" -Session
}
function Tidal-GetClients
{
	param
	(
		[uint32]$Limit, [uint32]$Offset, [switch]$AllItems # Pagination
	)
	Tidal-InvokeRequest "users/$($TidalSession.userId)/clients" -Limit:$Limit -Offset:$Offset -AllItems:$AllItems -Session
}
function Tidal-GetPurchases
{
	param
	(
		[Parameter(Mandatory=$true)]
		[ValidateSet('albums')] $Type,
		[uint32]$Limit, [uint32]$Offset, [switch]$AllItems # Pagination
	)
	Tidal-InvokeRequest "users/$($TidalSession.userId)/purchases/${Type}" -Limit:$Limit -Offset:$Offset -AllItems:$AllItems -RegionAndSession
}
function Tidal-GetUserPlaylists
{
	param
	(
		[uint32]$Limit, [uint32]$Offset, [switch]$AllItems # Pagination
	)
	# The path users/<userid>/playlists gives the set of personal playlists for
	# the user, but this is more of a filtered view of the set of all playlists
	# which are listed in the "playlists" path. Each playlist is identified by
	# a globally unique identifier (UUID).
	Tidal-InvokeRequest "users/$($TidalSession.userId)/playlists" -Limit:$Limit -Offset:$Offset -AllItems:$AllItems -RegionAndSession
}
function Tidal-CreateUserPlaylist($Title, $Description)
{
	$options = @{'title' = $Title; 'description' = $Description}
	Tidal-InvokeRequest "users/$($TidalSession.userId)/playlists" -Method Post -Options $options -RegionAndSession
}
function Tidal-RenamePlaylist($Id, $Title, $Description)
{
	$options = @{'title' = $Title; 'description' = $Description}
	Tidal-InvokeRequest "playlists/${Id}" -Method Post -Options $options -RegionAndSession
}
function Tidal-GetPlaylist($Id)
{
	Tidal-InvokeRequest "playlists/${Id}" -RegionAndSession
}
function Tidal-DeletePlaylist($Id)
{
	Tidal-InvokeRequest "playlists/${Id}" -Method Delete -RegionAndSession
}
function Tidal-GetPlaylistItems
{
	param
	(
		$Id,
		[ValidateSet('INDEX','NAME')] $Order, # TODO: What else?
		[ValidateSet('ASC','DESC')] $OrderDirection,
		[uint32]$Limit, [uint32]$Offset, [switch]$AllItems # Pagination
	)
	# A playlist contains items of type, where the type can be "track" or "video".
	$options = @{}
	if ($Order) { $options['order'] = $Order }
	if ($OrderDirection) { $options['orderDirection'] = $OrderDirection }
	Tidal-InvokeRequest "playlists/${Id}/items" -Options $options -Limit:$Limit -Offset:$Offset -AllItems:$AllItems -RegionAndSession
}
function Tidal-GetPlaylistItemsOfType
{
	param
	(
		$Id,
		[ValidateSet('tracks', 'videos')] $Type,
		[ValidateSet('INDEX','NAME')] $Order, # TODO: What else?
		[ValidateSet('ASC','DESC')] $OrderDirection,
		[uint32]$Limit, [uint32]$Offset, [switch]$AllItems # Pagination
	)
	# A playlist contains items of type, where the type for normal music is "track".
	$options = @{}
	if ($Order) { $options['order'] = $Order }
	if ($OrderDirection) { $options['orderDirection'] = $OrderDirection }
	Tidal-InvokeRequest "playlists/${Id}/${Type}" -Options $options -Limit:$Limit -Offset:$Offset -AllItems:$AllItems -RegionAndSession
}
function Tidal-GetPlaylistItemByIndex
{
	param
	(
		$Id,
		$Index,
		[ValidateSet('INDEX','NAME')] $Order, # TODO: What else?
		[ValidateSet('ASC','DESC')] $OrderDirection
	)
	# A playlist contains items of type, where the type can be "track" or "video".
	$options = @{}
	if ($Order) { $options['order'] = $Order }
	if ($OrderDirection) { $options['orderDirection'] = $OrderDirection }
	Tidal-InvokeRequest "playlists/${Id}/items/${Index}" -Options $options -RegionAndSession
}
function Tidal-EditPlaylist($Id)
{
	# Returns an "edit tag"; the value of the HTTP entity tag header in the response from server.
	# The value, which seems to be a timestamp, must be supplied when requesting a modification
	# and it will be checked by the server to ensure the playlist have not been modified by others
	# in the mean time (optimistic concurrency control).
	$response = Tidal-InvokeRequest "playlists/${Id}" -WebResponse -RegionAndSession
	$response.Headers['Etag'].Trim('"') #" (workaround for syntax parser being thrown off by the quoting)
}
function Tidal-AddPlaylistItems($PlaylistId, $EditTag, $ItemIds, $Position=0)
{
	# Adding tracks or videos (parameter is called "trackIds" for both) to a playlist.
	# The tracks/videos must be specified by their id, and can be a list of ids to
	# be added in the same operation!
	# NB: Must include the edit tag returned by EditPlaylist function, which is the
	# value from the HTTP entity tag (Etag) header, which will be checked by the server
	# as a form of optimistic concurrency control.
	$headers = @{'If-None-Match'="$EditTag"}
	$options = @{'trackIds'=$($ItemIds -join ','); 'toIndex'=$Position}
	Tidal-InvokeRequest "playlists/${PlaylistId}/items" -Method Post -Options $options -Headers $headers -RegionAndSession
}
function Tidal-RemovePlaylistItem($PlaylistId, $EditTag, $Index)
{
	# Removing item from playlist. Must specify item by its index in the playlist!
	# NB: Must include the edit tag returned by EditPlaylist function, which is the
	# value from the HTTP entity tag (Etag) header, which will be checked by the server
	# as a form of optimistic concurrency control.
	$headers = @{'If-None-Match'="$EditTag"}
	$options = @{'order'='INDEX';'orderDirection'='ASC'} # Important to have correct order when requesting index, and Web GUI sends these parameters, but it seems to be default if not specified.
	Tidal-InvokeRequest "playlists/${PlaylistId}/items/${Index}" -Method Delete -Options $options -Headers $headers -RegionAndSession
}
function Tidal-GetAlbum($Id)
{
	Tidal-InvokeRequest "albums/${Id}" -RegionAndSession
}
function Tidal-GetAlbumTracks
{
	param
	(
		$Id,
		[uint32]$Limit, [uint32]$Offset, [switch]$AllItems # Pagination
	)
	Tidal-InvokeRequest "albums/${Id}/tracks" -Limit:$Limit -Offset:$Offset -AllItems:$AllItems -RegionAndSession
}
function Tidal-GetAlbumCredits($Id)
{
	Tidal-InvokeRequest "albums/${Id}/credits" -RegionAndSession
}
function Tidal-GetArtist($Id)
{
	Tidal-InvokeRequest "artists/${Id}" -RegionAndSession
}
function Tidal-GetArtistAlbums
{
	param
	(
		$Id,
		[ValidateSet('ALL', 'ALBUMS', 'EPSANDSINGLES', 'COMPILATIONS')]
		$Type,
		[uint32]$Limit, [uint32]$Offset, [switch]$AllItems # Pagination
	)
	if ($Type) {
		$options = @{'filter' = $Type}
	} else {
		# If no filter it seems the API returns same as with the ALBUM filter.
		$options = @{}
	}
	Tidal-InvokeRequest "artists/${Id}/albums" -Options $options -Limit:$Limit -Offset:$Offset -AllItems:$AllItems -RegionAndSession
}
function Tidal-GetArtistTopTracks
{
	param
	(
		$Id,
		[uint32]$Limit, [uint32]$Offset, [switch]$AllItems # Pagination
	)
	Tidal-InvokeRequest "artists/${Id}/toptracks" -Limit:$Limit -Offset:$Offset -AllItems:$AllItems -RegionAndSession
}
function Tidal-GetArtistBio($Id)
{
	Tidal-InvokeRequest "artists/${Id}/bio" -RegionAndSession
}
function Tidal-GetArtistSimilar
{
	param
	(
		$Id,
		[uint32]$Limit, [uint32]$Offset, [switch]$AllItems # Pagination - TODO: Does not seem to work for this request?
	)
	Tidal-InvokeRequest "artists/${Id}/similar" -Limit:$Limit -Offset:$Offset -AllItems:$AllItems -RegionAndSession
}
function Tidal-GetArtistInfluencers
{
	param
	(
		$Id,
		[uint32]$Limit, [uint32]$Offset, [switch]$AllItems # Pagination
	)
	Tidal-InvokeRequest "artists/${Id}/influencers" -Limit:$Limit -Offset:$Offset -AllItems:$AllItems -RegionAndSession
}
function Tidal-GetArtistVideos
{
	param
	(
		$Id,
		[uint32]$Limit, [uint32]$Offset, [switch]$AllItems # Pagination
	)
	Tidal-InvokeRequest "artists/${Id}/videos" -Limit:$Limit -Offset:$Offset -AllItems:$AllItems -RegionAndSession
}
function Tidal-GetArtistPlaylists
{
	param
	(
		$Id,
		[uint32]$Limit, [uint32]$Offset, [switch]$AllItems # Pagination
	)
	Tidal-InvokeRequest "artists/${Id}/playlistscreatedby" -Limit:$Limit -Offset:$Offset -AllItems:$AllItems -RegionAndSession
}
function Tidal-GetArtistLinks
{
	param
	(
		$Id,
		[uint32]$Limit, [uint32]$Offset, [switch]$AllItems # Pagination
	)
	Tidal-InvokeRequest "artists/${Id}/links" -Limit:$Limit -Offset:$Offset -AllItems:$AllItems -RegionAndSession
}
function Tidal-GetArtistRadio
{
	param
	(
		$Id,
		[uint32]$Limit, [uint32]$Offset, [switch]$AllItems # Pagination
	)
	Tidal-InvokeRequest "artists/${Id}/radio" -Limit:$Limit -Offset:$Offset -AllItems:$AllItems -RegionAndSession
}
function Tidal-GetTrack($Id)
{
	Tidal-InvokeRequest "tracks/${Id}" -RegionAndSession
}
function Tidal-GetTrackStreamURL
{
	param
	(
		$Id,
		[ValidateSet('LOSSLESS', 'HIGH', 'LOW')]
		$Quality = $TidalSubscription.highestSoundQuality
	)
	Tidal-InvokeRequest "tracks/${Id}/streamUrl" -Options @{'soundQuality'=$Quality} -RegionAndSession
}
function Tidal-GetTrackOfflineURL
{
	param
	(
		$Id,
		[ValidateSet('LOSSLESS', 'HIGH', 'LOW')]
		$Quality = $TidalSubscription.highestSoundQuality
	)
	Tidal-InvokeRequest "tracks/${Id}/offlineUrl" -Options @{'soundQuality'=$Quality} -RegionAndSession
}
function Tidal-GetTrackVideoStreamUrl($Id)
{
	Tidal-InvokeRequest "videos/${Id}/streamUrl" -RegionAndSession
}
function Tidal-GetTrackRadio
{
	param
	(
		$Id,
		[uint32]$Limit, [uint32]$Offset, [switch]$AllItems # Pagination
	)
	Tidal-InvokeRequest "tracks/${Id}/radio" -Limit:$Limit -Offset:$Offset -AllItems:$AllItems -RegionAndSession
}
function Tidal-GetTrackRecommendations
{
	param
	(
		$Id,
		[uint32]$Limit, [uint32]$Offset, [switch]$AllItems # Pagination
	)
	Tidal-InvokeRequest "tracks/${Id}/recommendations" -Limit:$Limit -Offset:$Offset -AllItems:$AllItems -RegionAndSession
}
function Tidal-GetPromotions
{
	param
	(
		[ValidateSet('RISING')] $Type, # TODO: What else are valid input?
		[ValidateSet('BROWSER')] $ClientType, # TODO: What else are valid input?
		[uint32]$Limit, [uint32]$Offset, [switch]$AllItems # Pagination
	)
	$options = @{}
	if ($Type) { $options['group'] = $Type }
	if ($ClientType) { $options['clientType'] = $ClientType }
	Tidal-InvokeRequest "promotions" -Options $options -Limit:$Limit -Offset:$Offset -AllItems:$AllItems -RegionAndSession
}
function Tidal-GetNews
{
	param
	(
		[ValidateSet('BROWSER')]
		$DeviceType = 'BROWSER', # TODO: What else are valid input?
		
		$Locale = 'nb_NO'
	)
	Tidal-InvokeRequest "pages/whatsnew" -Options @{'deviceType'=$DeviceType;'locale'=$Locale} -RegionAndSession # Both deviceType and locale are required parameters!
}

#
# Search
#

function Tidal-Search
{
	param
	(
		$Query,
		[ValidateSet('playlists', 'artists', 'albums', 'tracks', 'videos')]
		$Types = @('playlists','artists','albums','tracks','videos'),
		[uint32]$Limit, [uint32]$Offset #, [switch]$AllItems # Pagination. NB: Results are groupd into types, so AllItems does not work!
	)
	$options += @{ 'query' = $Query; 'types' = $($Types -join ',') }
	Tidal-InvokeRequest "search" -Options $options -Limit:$Limit -Offset:$Offset -RegionAndSession
}

#
# Categories
#

function Tidal-GetRising
{
	# Category type of request; rising, featured, moods, genres, shows and movies are handled very similarly!
	# The result contains a list of rising categories, with locale translated
	# name, API path, and properties hasPlaylists, hasArtists etc. indicating
	# what type of items they contain.
	# Currently I have only seen one category: path "new".
	Tidal-InvokeRequest "rising" -RegionAndSession
}
function Tidal-GetRisingItems
{
	param
	(
		$Category = 'new', # Possible categories are returned by the "rising" request
		[ValidateSet('playlists', 'artists', 'albums', 'tracks', 'videos')] $Type,
		[uint32]$Limit, [uint32]$Offset, [switch]$AllItems # Pagination
	)
	# Category type of request; rising, featured, moods, genres, shows and movies are handled very similarly!
	# Category is required argument. If no type is specified then we get the
	# category information as is included in the parent "rising" request,
	# with locale translated name, API path, and properties hasPlaylists,
	# hasArtists etc. indicating what type of items they contain.
	# Currently I have only seen one category: path "new".
	Tidal-InvokeRequest "rising/${Category}/${Type}" -Limit:$Limit -Offset:$Offset -AllItems:$AllItems -RegionAndSession
}
function Tidal-GetFeatured
{
	# Category type of request; rising, featured, moods, genres, shows and movies are handled very similarly!
	# The result contains a list of featured categories, with locale translated
	# name, API path, and properties hasPlaylists, hasArtists etc. indicating
	# what type of items they contain.
	# Currently I have only seen: new, recommended, top, local and exlusive
	Tidal-InvokeRequest "featured" -RegionAndSession
}
function Tidal-GetFeaturedItems
{
	param
	(
		$Category, # Possible categories are returned by the "featured" request
		[ValidateSet('playlists', 'artists', 'albums', 'tracks', 'videos')]
		$Type,
		[uint32]$Limit, [uint32]$Offset, [switch]$AllItems # Pagination
	)
	# Category type of request; rising, featured, moods, genres, shows and movies are handled very similarly!
	# TODO: The result from featured/${Id} contains properties
	# hasPlaylists, hasArtists etc. indicating what item types
	# are supported for this id.
	Tidal-InvokeRequest "featured/${Category}/${Type}" -Limit:$Limit -Offset:$Offset -AllItems:$AllItems -RegionAndSession
}
function Tidal-GetMoods($Id)
{
	# Category type of request; rising, featured, moods, genres, shows and movies are handled very similarly!
	Tidal-InvokeRequest "moods" -RegionAndSession
}
function Tidal-GetMoodItems
{
	param
	(
		$Category,
		[ValidateSet('playlists', 'artists', 'albums', 'tracks', 'videos')]
		$Type,
		[uint32]$Limit, [uint32]$Offset, [switch]$AllItems # Pagination
	)
	# Category type of request; rising, featured, moods, genres, shows and movies are handled very similarly!
	# TODO: For moods "playlists" seems to be the only used content type!?
	Tidal-InvokeRequest "moods/${Category}/${Type}" -Limit:$Limit -Offset:$Offset -AllItems:$AllItems -RegionAndSession
}
function Tidal-GetGenres($Id)
{
	# Category type of request; rising, featured, moods, genres, shows and movies are handled very similarly!
	Tidal-InvokeRequest "genres" -RegionAndSession
}
function Tidal-GetGenreItems
{
	param
	(
		$Category,
		[ValidateSet('playlists', 'artists', 'albums', 'tracks', 'videos')]
		$Type,
		[uint32]$Limit, [uint32]$Offset, [switch]$AllItems # Pagination
	)
	# Category type of request; rising, featured, moods, genres, shows and movies are handled very similarly!
	Tidal-InvokeRequest "genres/${Category}/${Type}" -Limit:$Limit -Offset:$Offset -AllItems:$AllItems -RegionAndSession
}
function Tidal-GetShows()
{
	# Category type of request; rising, featured, moods, genres, shows and movies are handled very similarly!
	Tidal-InvokeRequest "shows" -RegionAndSession
}
function Tidal-GetShowsItems
{
	param
	(
		$Category = 'new', # Possible categories are returned by the "movies" request. Only seen "new" for shows!?
		[ValidateSet('playlists', 'artists', 'albums', 'tracks', 'videos')] # Only seen "playlists" for shows!?
		$Type = 'playlists',
		[uint32]$Limit, [uint32]$Offset, [switch]$AllItems # Pagination
	)
	# Category type of request; rising, featured, moods, genres, shows and movies are handled very similarly!
	Tidal-InvokeRequest "shows/${Category}/${Type}" -Limit:$Limit -Offset:$Offset -AllItems:$AllItems -RegionAndSession
}
function Tidal-GetMovies()
{
	# Category type of request; rising, featured, moods, genres, shows and movies are handled very similarly!
	Tidal-InvokeRequest "movies" -RegionAndSession
}
function Tidal-GetMoviesItems
{
	param
	(
		$Category = 'new', # Possible categories are returned by the "movies" request. Only seen "new" for movies!?
		[ValidateSet('playlists', 'artists', 'albums', 'tracks', 'videos')] # Only "videos" is relevant for movies!?
		$Type = 'videos',
		[uint32]$Limit, [uint32]$Offset, [switch]$AllItems # Pagination
	)
	# Category type of request; rising, featured, moods, genres, shows and movies are handled very similarly!
	Tidal-InvokeRequest "movies/${Category}/${Type}" -Limit:$Limit -Offset:$Offset -AllItems:$AllItems -RegionAndSession
}

#
# Favorites
#

function Tidal-GetUserFavoritesLastUpdated($Id)
{
	# Base url for favorites requests, but query also returns timestamps last updated.
	Tidal-InvokeRequest "users/$($TidalSession.userId)/favorites" -RegionAndSession
}
function Tidal-GetUserFavoritesIds($Id)
{
	# Gets the ids of favorites grouped on categories (playlist, artist, album, track and video)
	Tidal-InvokeRequest "users/$($TidalSession.userId)/favorites/ids" -RegionAndSession
}
function Tidal-GetUserFavorites
{
	param
	(
		[ValidateSet('playlists', 'artists', 'albums', 'tracks', 'videos')] $Type,
		[uint32]$Limit, [uint32]$Offset, [switch]$AllItems # Pagination
	)
	Tidal-InvokeRequest "users/$($TidalSession.userId)/favorites/${Type}" -Limit:$Limit -Offset:$Offset -AllItems:$AllItems -RegionAndSession
}
function Tidal-AddToUserFavorites
{
	param
	(
		$Id,
		[ValidateSet('playlist', 'artist', 'album', 'track', 'video')]
		$Type
	)
	Tidal-InvokeRequest "users/$($TidalSession.userId)/favorites/${Type}s" -Method Post -Options @{"${Type}Id"=$Id} -RegionAndSession
}
function Tidal-RemoveFromUserFavorites
{
	param
	(
		$Id,
		[ValidateSet('playlist', 'artist', 'album', 'track', 'video')]
		$Type
	)
	Tidal-InvokeRequest "users/$($TidalSession.userId)/favorites/${Type}s/${Id}" -Method Delete -RegionAndSession
}

#
# Image resources
#

function Tidal-ShowImage($url)
{
	Start-Process -FilePath $url
}

function Tidal-GetImageUrl
{
	# Items such as genres, albums etc. often have a related image,
	# in the form of attributes such as cover, image etc in the item
	# response, and the value of these attributes are UUID.
	# The image files seems to be all stored at resources.tidal.com
	# in path images and a subpath based on the UUID, and filename
	# is the resolution "<width>x<Height>.jpg".
	# Some, like promotions, have the full resource url in property
	# "imageURL" in addition to the image UUID in property "imageId".
	# TODO: Is there a way to get information about the actual image sizes
	# available, or do we just have to know that in advance?
	# Some observed sizes:
	#  Albums (cover art), and also on tracks(?): 80x80, 160x160, 320x320, 640x640, and 1280x1280.
	#  Artists: 640x428
	#  Genres: 460x306 and 2048x512.
	#  Moods: 342x324
	#  Promotions: 550x400
	#  Videos, movies and shows: 160x107, 320x214 and 1080x720.
	#  Playlists: 1080x720
	#  Unknown: 640x248
	param
	(
		$Id,
		[uint32]$Width = 80,
		[uint32]$Height = $Width
	)
	"https://resources.tidal.com/images/$($Id -replace '-','/')/${Width}x${Height}.jpg"
}
function Tidal-GetCoverArtUrl
{
	param
	(
		$Id,
		[ValidateSet(80,160,320,640,1280)]
		[uint32]$Size = 1280
	)
	# Albums (cover art), and also on tracks(?): 80x80, 160x160, 320x320, 640x640, and 1280x1280.
	Tidal-GetImageUrl $Id $Size $Size
}
function Tidal-GetArtistImageUrl
{
	param
	(
		$Id,
		[ValidateSet(640)]
		[string]$Width = 640
	)
	# Artists: 640x428
	switch ($Width) {
		640 { $Height = 248 }
		default { $Height = $Width }
	}
	Tidal-GetImageUrl $Id $Width $Height
}
function Tidal-GetGenreImageUrl
{
	param
	(
		$Id,
		[ValidateSet(460,2048)]
		[string]$Width = 460
	)
	# Genres: 460x306 and 2048x512.
	switch ($Width) {
		460 { $Height = 306 }
		2048 { $Height = 512 }
		default { $Height = $Width }
	}
	Tidal-GetImageUrl $Id $Width $Height
}
function Tidal-GetPromotionImageUrl
{
	param
	(
		$Id,
		[ValidateSet(550)]
		[string]$Width = 550
	)
	# Promotions: 550x400
	# NB: Promotions are a bit special since they have the full resource url in
	# property "imageURL" in addition to the image UUID in property "imageId".
	switch ($Width) {
		550 { $Height = 400 }
		default { $Height = $Width }
	}
	Tidal-GetImageUrl $Id $Width $Height
}
function Tidal-GetVideoImageUrl
{
	param
	(
		$Id,
		[ValidateSet(160,320,1080)]
		[string]$Width = 160
	)
	# Videos, movies and shows: 160x107, 320x214 and 1080x720.
	switch ($Width) {
		160 { $Height = 107 }
		320 { $Height = 214 }
		1080 { $Height = 720 }
		default { $Height = $Width }
	}
	Tidal-GetImageUrl $Id $Width $Height
}

#
# Some examples of more top level functionality
#

function Tidal-ExportPlaylist
{
	param
	(
		[Parameter(Mandatory = $true)] $Name
	)
	$playlist = Tidal-GetUserPlaylists -AllItems | ? title -eq $Name
	if ($playlist) {
		Tidal-GetPlaylistItems $playlist.uuid -AllItems | ConvertTo-Json
	} else {
		Write-Error "Playlist with name `"${Name}`" not found"
	}
}

function Tidal-ImportPlaylist
{
	param
	(
		[Parameter(Mandatory = $true)] $Content,
		[Parameter(Mandatory = $true)] $Name
	)
	$playlist = Tidal-GetUserPlaylists -AllItems | ? title -eq $Name
	if (!$playlist) {
		$itemIds = ((ConvertFrom-Json $content) | select -expand item | select -expand id) -join ','
		if ($itemIds.Count -gt 0) {
			$playlist = Tidal-CreateUserPlaylist $Name
			$etag = Tidal-EditPlaylist $playlist.uuid
			Tidal-AddPlaylistItems $playlist.uuid $etag $itemIds
		} else {
			Write-Error "Supplied content does not contain any items"
		}
	} else {
		Write-Error "Playlist with name `"${Name}`" already exists"
	}
}

function Tidal-ExportFavorites
{
	param
	(
		[Parameter(Mandatory = $true)][ValidateSet('playlists', 'artists', 'albums', 'tracks', 'videos')] $Type
	)
	$favorites = Tidal-GetUserFavorites $Type -AllItems
	if ($favorites) {
		$favorites | ConvertTo-Json
	} else {
		Write-Warning "No favorites of type `"${Type}`" found"
	}
}

function Tidal-ImportFavorites
{
	param
	(
		[Parameter(Mandatory = $true)] $Content,
		[Parameter(Mandatory = $true)][ValidateSet('playlist', 'artist', 'album', 'track', 'video')] $Type
	)
	$itemIds = (ConvertFrom-Json $content) | select -expand item | select -expand id
	if ($itemIds.Count -gt 0) {
		$itemIds | % { Tidal-AddToUserFavorites $_ $Type }
	} else {
		Write-Error "Supplied content does not contain any items"
	}
}

function Tidal-GetAllUserPlaylistsWithTracksAsCsv
{
	# Get all user playlists, with tracks as CSV file.
	# Includes name and id of all user playlists, and for each of them the title,
	# id, isrc (International Standard Recording Code), and duration of all tracks,
	# as well as the id and name of of the each track's artist and the id and name
	# of the album they are from!
	"playlist_uuid;playlist_title;track_id;track_isrc;track_duration;track_title;artist_id;artist_name;album_id;album_title"
	$batchSize = 10
	Tidal-GetUserPlaylists -Limit $batchSize -AllItems | `
		% { $playlist = $_; Tidal-GetPlaylistItemsOfType $playlist.uuid 'tracks' -Limit $batchSize -AllItems | `
			% { "$($playlist.uuid);$($playlist.title);$($_.id);$($_.title);$($_.isrc);$($_.duration);$($_.artist.id);$($_.artist.name);$($_.album.id);$($_.album.title)" } }
}

function Tidal-GetAllUserPlaylistsWithTracks
{
	# Get all user playlists, with tracks. 
	# Returns structured data with name and id of all user playlists,
	# and for each of them the title, id, isrc (International Standard Recording Code),
	# and duration of all tracks, as well as the id and name of of the each
	# track's artist and the id and name of the album they are from!
	# Result can be converted to JSON for backup purposes, by sending
	# results into: ConvertTo-Json -Depth 4
	$batchSize = 10
	Tidal-GetUserPlaylists -Limit $batchSize -AllItems | `
		% { $playlist = $_; $tracks = @(); `
			Tidal-GetPlaylistItemsOfType $playlist.uuid 'tracks' -Limit $batchSize -AllItems | `
				% { $tracks += @{ 'id'=$_.id; 'title' = $_.title; 'isrc' = $_.isrc; 'duration' = $_.duration; 'artist' = @{ 'id' = $_.artist.id; 'name' = $_.artist.name }; 'album' = @{'id' = $_.album.id; 'title' = $_.album.title } } }; `
			@{'uuid'=$playlist.uuid;'title'=$playlist.title;'tracks'=$tracks} }
}

function Tidal-GetAllUserPlaylistsWithTracksAsJson
{
	Tidal-GetAllUserPlaylistsWithTracks | ConvertTo-Json -Depth 4
}

function Tidal-PlayTrack
{
	# Play track stream using VLC (prerequisite)
	param
	(
		$Id,
		[ValidateSet('LOSSLESS', 'HIGH', 'LOW')]
		$Quality = $TidalSubscription.highestSoundQuality,
		$Vlc = "vlc"
	)
	$res = Tidal-GetTrackStreamURL $Id $Quality
	&$vlc "rtmp://$($res.url)" --qt-start-minimized --play-and-exit
}

function Trim-Length {
	# Helper function for trimming a string by removing whitespaces from both
	# ends, with the optional addition of limiting to a maximum length.
    param(
        [parameter(ValueFromPipeline=$True)][string] $Str,
        [parameter(Mandatory=$true,Position=1)][ValidateRange(1,[int]::MaxValue)][int] $Length
    )
    ($Str.TrimStart()[0..($Length-1)] -join "").TrimEnd()
}

function Expand-Properties {
    # Helper function to generate a string based on provided pattern and object,
    # expanding any properties specified with %PropertyName|format%
	# using the value of the given property for the input object.
	# The property name can be multiple levels, such as "artist.name".
	# TODO: Does not support any kind of filtering, e.g. to only get the name
	# of the main artist for a specified track.
    param(
        [Parameter(Mandatory=$true)][psobject]$InputObject,
        [Parameter(Mandatory=$true)][String]$Pattern
    )
    $RegEx = '(?:\%)(.+?)(?:(?:\|)(.*?))?(?:\%)'
    $expandedString = $Pattern
    while ($expandedString -match $RegEx) {
        $match = $Matches[0]
        $propertyPath = $Matches[1]
        if ($Matches.Count -ge 3) {
            $format = $Matches[2]
        } else {
            $format = ""
        }
		$propertyValue = $InputObject
		foreach ($property in $propertyPath -split "\.") {
			$propertyValue = $propertyValue.($property)
		}
        if ($format -match '^[\d]+$') { # if format is just an integer value then treat it as max length
            $expandedString = $expandedString.Replace($match, ($propertyValue | Trim-Length $format))
        } else {
            $expandedString = $expandedString.Replace($match, "{0:$format}" -f $propertyValue)
        }
    }
    $expandedString
}

function Get-ValidFileName {
	# Helper function to convert a string into a legal name of a file or folder.
    param
	(
		[Parameter(Mandatory=$true)][String] $FileName,
		[Parameter(Mandatory=$false)][String] $Replacement = '_'
	)
    foreach ($char in ([System.IO.Path]::GetInvalidFileNameChars())) {
        $FileName = $FileName.Replace($char, $Replacement)
    }
    $FileName.Trim()
}

function Tidal-SaveTrack
{
	# Save track stream using VLC (prerequisite).
	# TODO: Not considering lossless file formats yet.
	# TODO: TrackStreamURL response contains information about soundQuality and codec...
	# TODO: Consider additional VLC options:
	#			--no-drop-late-frames
	# 			--no-skip-frames
	# 			--no-ffmpeg-hurry-up
	# 			--no-sout-video
	# 			--network-caching
	# 			--rtsp-frame-buffer-size
	# 			--rtp-max-dropout
	# 			--rtp-max-misorder
	#			--file-logging --logfile=vlc-log.txt --log-verbose=3
	param
	(
		$Id,
		$OutputFolder = ".", # Folder must exist!
		$FileName = "%artist.name% - %album.title% - %trackNumber|d2% - %title%.m4a", # Both file extension .mp4 and .m4a are used, both indicates the same MPEG-4 Part 14 container format.
		[ValidateSet('LOSSLESS', 'HIGH', 'LOW')]
		$Quality = $TidalSubscription.highestSoundQuality,
		$Vlc = "vlc",
		$Options = @(),
		[switch] $Overwrite
	)
	$stream = Tidal-GetTrackStreamURL $Id $Quality
	if (-not $stream) { return }
	$track = Tidal-GetTrack $Id
	if (-not $track) { return }
	$expandedFolderPath = Resolve-Path $OutputFolder -ErrorAction Stop
	$expandedFileName = Get-ValidFileName (Expand-Properties $track $FileName)
	$outputFilePath = Join-Path $expandedFolderPath $expandedFileName
	if (-not $Overwrite -and (Test-Path -LiteralPath $outputFilePath))
	{
		Write-Warning "Output path already exists: ${outputFilePath}"
	}
	else
	{
		Write-Host "Streaming track ${Id} - $($track.artist.name) - $($track.album.title) - $($track.trackNumber) - $($track.title)..."
		Write-Host "Writing to file $outputFilePath..."
		#&$vlc rtmp://$($stream.url) --sout file/mp4:${File} --qt-start-minimized --play-and-exit
		Start-Process -Wait -FilePath $vlc -ArgumentList ("rtmp://$($stream.url)","--sout file/mp4:`"${outputFilePath}`"","--qt-start-minimized","--play-and-exit" + $Options)
	}
}

function Tidal-GetArtistByName($Name)
{
	(Tidal-Search $Name artists).artists.items[0]
}

function Tidal-GetSimilarArtists
{
	# Given an artist by name, get artists similar to it.
	param
	(
		[string]$Name,
		[uint32]$Limit, [uint32]$Offset, [switch]$AllItems # Pagination - TODO: Does not seem to work for Tidal-GetArtistSimilar?
	)
	Tidal-GetArtistSimilar (Tidal-GetArtistByName $Name).id -Limit:$Limit -Offset:$Offset -AllItems:$AllItems
}

function Tidal-GetSimilarArtistsMultiLevelInternal
{
	# Internal recursive function, only to be called by "public" wrapper function.
	param
	(
		$Artist, # Object with .name and .id of artist, as returned from Get-Artist
		[uint32]$BranchLimit = 0, # Maximum number of immediate similar artists to retrieve for each artist (but will recurse on each of them according to -Depth).
		[uint32]$Depth = 3,
		[ref]$ArtistsFound # Mostly for internal use; keeping track of recursion state to avoid loops (artist a similar to artist b and artist b similar to artist a)
	)
	try
	{
		if ($BranchLimit -gt 0) {
			$similarArtists = (Tidal-GetArtistSimilar $Artist.id -Limit $BranchLimit).items[0..($BranchLimit-1)] # NOTE: Slicing the array as a workaround for -Limit not working on Tidal-GetArtistSimilar.
		} else {
			$similarArtists = Tidal-GetArtistSimilar $Artist.id -AllItems
		}
		foreach ($similar in $similarArtists) {
			if ($ArtistsFound.value.name -notcontains $similar.name) {
				$ArtistsFound.value += @($similar)
				if ($Depth -gt 1) {
					&$MyInvocation.MyCommand $similar $BranchLimit ($Depth - 1) $ArtistsFound
				}
			}
		}
	} catch {}
}
function Tidal-GetSimilarArtistsMultiLevel
{
	# Given an artist by name, get artists similar to it, and recursively artists similar to those again up to specified Depth.
	# Can optionally specify branching limit: A maximum number of immediate similar artists to retrieve for each artist.
	# Note that there will be recursion for each of the artists within the branching limit so the maximum number of results
	# is given by the expression Depth*BranchLimit. Also note that multiple artists are similar to same artists (which is often
	# the case), then we do not make effort to fetch new similar artists up to branching limit: If, for a given artist, there
	# are only similar artists that have already been handled within the branch limit, then no further recursion is performed
	# on this artist.
	param
	(
		[string]$Name,
		[uint32]$BranchLimit = 0,
		[uint32]$Depth = 3
	)
	$ArtistsFound = @()
	$Artist = (Tidal-Search $Name artists).artists.items[0]
	Tidal-GetSimilarArtistsMultiLevelInternal $Artist $BranchLimit $Depth ([ref]$ArtistsFound)
	$ArtistsFound | ?{$_.id -ne $Artist.id} # Remove the input artist from the list (it will often end up in the list because if artist a is similar to artist b then artist b is similar to artist a as well).
}

function Tidal-GetArtistSimilaritiesInternal
{
	# Internal recursive function, only to be called by "public" wrapper function.
	param
	(
		$Artist, # Object with .name and .id of artist, as returned from Get-Artist
		[uint32]$BranchLimit = 5,
		[uint32]$Depth = 3,
		[ValidateSet('yUML', 'DOT')]$Format = 'yUML',
		[ref]$ArtistsFound # Mostly for internal use; keeping track of recursion state to avoid loops (artist a similar to artist b, b similar to c, and then c similar to a again)
	)
	try
	{
		$ArtistsFound.value += @($Artist.name)
		if ($BranchLimit -gt 0) {
			$similarArtists = (Tidal-GetArtistSimilar $Artist.id -Limit $BranchLimit).items[0..($BranchLimit-1)] # NOTE: Slicing the array as a workaround for -Limit not working on Tidal-GetArtistSimilar.
		} else {
			$similarArtists = Tidal-GetArtistSimilar $Artist.id -AllItems
		}
		foreach ($similar in $similarArtists)
		{
			if ($Format -eq 'DOT') {
				"`"$($Artist.name)`" -> `"$($similar.name)`";"
			} else {
				"[$($Artist.name)] -> [$($similar.name)]"
			}
			if ($Depth -gt 1) {
				if ($ArtistsFound.value -notcontains $similar.name) {
					&$MyInvocation.MyCommand $similar $Branching ($Depth - 1) $Format $ArtistsFound
				} else {
					#Write-Warning "Artist $($similar.name) already processed"
				}
			}
		}
	} catch {}
}

function Tidal-GetArtistSimilarities
{
	# Given an artist by name, get artists similar to it, and recursively artists similar to those again up to specified Depth,
	# and keep track of the dependencies in a graph description language.
	# Examples:
	#   Basic, returning plain text in yUML compatible format: [artist] -> [similar_artist]
	#     Tidal-GetArtistSimilarities Alaska 5 2
	#   Using the yuml.me Web API to generate a PNG image on the fly:
	#     $yumlDSL = Tidal-GetArtistSimilarities Alaska 5 2
	#     $yumlImageId = Invoke-RestMethod -Uri https://yuml.me/diagram/plain/class -Body "dsl_text=$($yumlDSL -join ', ')" -Method Post
	#     $yumlImageUrl = "https://yuml.me/${yumlImageId}"
	#     Start-Process $yumlImageUrl
	#   Using DOT (the graph description language) format and executing dot.exe to generate PNG image on the fly:
	#     Tidal-GetArtistSimilarities Alaska 5 2 -DotFormat | dot.exe -T png -o Alaska.png
	#     Invoke-Item Alaska.png
	param
	(
		[string]$Name,
		[uint32]$Branching = 5,
		[uint32]$Depth = 3,
		[ValidateSet('yUML', 'DOT')]$Format = 'yUML'
	)
	if ($Format -eq 'DOT') {
		"digraph {"
	}
	$ArtistsFound = @()
	Tidal-GetArtistSimilaritiesInternal (Tidal-Search $Name artists).artists.items[0] $Branching $Depth $Format ([ref]$ArtistsFound)
	if ($Format -eq 'DOT') {
		"}"
	}
}
function Tidal-PlotArtistSimilarities
{
	# Given an artist by name, get artists similar to it, and recursively artists similar to those again up to specified Depth,
	# and plot the dependencies in a graph using yUML web service or DOT command line utility.
	param
	(
		[string]$Name,
		[uint32]$Branching = 5,
		[uint32]$Depth = 3,
		[ValidateSet('yUML', 'DOT')]$Format = 'yUML', # If DOT we are assuming dot.exe is in PATH
		$OutFile # Path to file to store generated image in. When using yUML format and output file not specifying output file the generated image on remote web service is shown in default browser.
	)
	if ($Format -eq 'DOT') {
		if (-not $OutFile) {
			# When using DOT format we must save as file on disk.
			$OutFile = "Tidal-${Name}-similarities.png"
		}
		Tidal-GetArtistSimilarities $Name $Branching $Depth $Format | dot.exe -T png -o $OutFile
		Invoke-Item $OutFile
	} else {
		$yumlDSL = Tidal-GetArtistSimilarities $Name $Branching $Depth $Format
		$yumlImageId = Invoke-RestMethod -Uri "https://yuml.me/diagram/plain/class" -Body "dsl_text=$([uri]::EscapeDataString(($yumlDSL -join ',')))" -Method Post
		$yumlImageUrl = "https://yuml.me/${yumlImageId}"
		if ($OutFile) {
			Invoke-WebRequest $yumlImageUrl -OutFile $OutFile
		} else {
			Start-Process $yumlImageUrl
		}
	}
}
