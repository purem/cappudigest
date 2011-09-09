var sharedAuthenticationController = nil;

@implementation J2AuthenticationController : CPObject
{
    // To prevent MITM replay attacks
    CPInteger nonceCounter;

    //Authentication headers returned from the server
    CPDictionary wwwAuthenticateDict;

    // Use ha1 for each request and not raw password - keep password in variable for
    // as short as possible
    CPString ha1;

    // Username for use in other parts of the application
    CPString username @accessors;

    id delegate @accessors;
}

// Singleton instance access method
+ (id)sharedAuthenticationController
{
    if (sharedAuthenticationController == nil)
    {
        sharedAuthenticationController = [[J2AuthenticationController alloc] init];
    }

    return sharedAuthenticationController;
}

+ (CPDictionary)parseAuthenticationHeader:(CPString)authHeader
{
    var authDict = {};

    // Everything escaped needs escaping twice, once for javascript and then for the
    // regex. Matches key="value" and key=value with optional space after =.
    var regex = new RegExp('(\\w+)[=] ?\\"?(\\w+)\\"?', "g");

    while (match = regex.exec(authHeader))
    {
        authDict[match[1]] = match[2];
    }

    return authDict;
}

+ (CPString)ha1forUsername:(CPString)username realm:(CPString)realm password:(CPString)password
{
    return hex_md5(username+":"+realm+":"+password);
}

+ (CPString)genClientNonce {

    var cnonce = "";
    for (var i = 0; i < 20; i++) {
    	cnonce += Math.floor(Math.random()*16);
    }
     return cnonce;
}

- (id)init
{
	if (self = [super init])
	{
            self.nonceCounter = 0;
            self.wwwAuthenticateDict = nil;
	}

	return self;
}

- (id)initWithDelegate:(id)delegate
{
    self = [self init];
    [self setDelegate:delegate];
}

// CPURLConnection Class Delegate
- (void)connectionDidReceiveAuthenticationChallenge:(id)aConnection
{
    var authHeader = aConnection._HTTPRequest.getResponseHeader("X-WWW-Authenticate");
    var request = aConnection._request;

    //Show login dialog and get username and password
    if (self.delegate && [self.delegate respondsToSelector:@selector(authenticationControllerRequestedUserCredentials:)])
    {
        userPassDict = [self.delegate authenticationControllerRequestedUserCredentials:self];
        console.log("test");
        self.username = userPassDict.username;
        self.wwwAuthenticateDict = [J2AuthenticationController parseAuthenticationHeader:authHeader];
        self.nonceCounter = 0;
        console.log(self.wwwAuthenticateDict);
        self.ha1 = [J2AuthenticationController ha1forUsername:self.username realm:self.wwwAuthenticateDict.realm password:userPassDict.password];

        // Restart the connection
        [aConnection cancel];
        [aConnection start];
    }
}

- (CPString)authorizationHeaderForRequest:(CPHTTPRequest)request
{
    console.log(_cmd);
    var authorizationFields = [];
    var cnonce = [J2AuthenticationController genClientNonce];

    authorizationFields.push("Digest username="+'"'+self.username+'"');
    authorizationFields.push("realm="+'"'+ self.wwwAuthenticateDict.realm+'"');
    authorizationFields.push("nonce="+'"'+self.wwwAuthenticateDict.nonce+'"');
    authorizationFields.push("uri="+'"'+[[request URL] path]+'"');
    authorizationFields.push("qop="+'"'+self.wwwAuthenticateDict.qop+'"');
    authorizationFields.push("nc="+self.nonceCounter);
    authorizationFields.push("cnonce="+'"'+cnonce+'"');
    authorizationFields.push("opaque="+'"'+ self.wwwAuthenticateDict.opaque +'"');

    var a2;
    if(self.wwwAuthenticateDict.qop == nil || self.wwwAuthenticateDict.qop == "auth") {
            a2 = hex_md5([request HTTPMethod]+":"+[[request URL] path]);
    }

    // response is MD5("A1:<nonce>:<nc>:<cnonce>:<qop>:A2")
    var response = hex_md5(self.ha1+":"+self.wwwAuthenticateDict.nonce+":"+self.nonceCounter+":"+ cnonce +":"+self.wwwAuthenticateDict.qop+":"+a2);
    authorizationFields.push("response="+'"'+response+'"');

    //Increment nonce counter for next request
    self.nonceCounter++;

    // Join into comma delimited string
    return authorizationFields.join(',');
}


- (BOOL)requiresAuthentication
{
    console.log(self);
    return (self.wwwAuthenticateDict != nil);
}

@end


// Hook into CPURLConnection so that each request is authenticated
@implementation CPURLConnection (Authentication)

// Copied from CPURLConnection
- (void)start {
    _isCanceled = NO;
    try
    {
        _HTTPRequest.open([_request HTTPMethod], [[_request URL] absoluteString], YES);

        _HTTPRequest.onreadystatechange = function() { [self _readyStateDidChange]; }

        var fields = [_request allHTTPHeaderFields],
            key = nil,
            keys = [fields keyEnumerator];

        while (key = [keys nextObject])
            _HTTPRequest.setRequestHeader(key, [fields objectForKey:key]);

        // Added code - Check if we have server authentication details and check if we
        // do
        if ([[J2AuthenticationController sharedAuthenticationController] requiresAuthentication])
        {
           _HTTPRequest.setRequestHeader("Authorization", [[J2AuthenticationController sharedAuthenticationController] authorizationHeaderForRequest:_request]);
        }
        nonceCounter++;
        _HTTPRequest.send([_request HTTPBody]);
    }
    catch (anException)
    {
        if ([_delegate respondsToSelector:@selector(connection:didFailWithError:)])
            [_delegate connection:self didFailWithError:anException];
    }
}

@end

// Register as global authentication delegate
[CPURLConnection setClassDelegate:[J2AuthenticationController sharedAuthenticationController]];
