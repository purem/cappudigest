/*
 * AppController.j
 * digesttest
 *
 * Created by You on August 29, 2011.
 * Copyright 2011, Your Company All rights reserved.
 */
@import "md5.js"
@import <Foundation/CPObject.j>
@import "J2AuthenticationController.j"
nonceCounter = 000000;

@implementation AppController : CPObject
{
}

- (void)applicationDidFinishLaunching:(CPNotification)aNotification
{

    [[J2AuthenticationController sharedAuthenticationController] setDelegate:self];

    var theWindow = [[CPWindow alloc] initWithContentRect:CGRectMakeZero() styleMask:CPBorderlessBridgeWindowMask],
        contentView = [theWindow contentView];
    [J2AuthenticationController sharedAuthenticationController];
    var label = [CPButton buttonWithTitle:"connection"];

    [label setAutoresizingMask:CPViewMinXMargin | CPViewMaxXMargin | CPViewMinYMargin | CPViewMaxYMargin];
    [label setCenter:[contentView center]];
	[label setAction:@selector(newConnection:)]
	[label setTarget:self];
    [contentView addSubview:label];

    [theWindow orderFront:self];

}

- (void)newConnection:(id)sender
{
    var request = [CPURLRequest requestWithURL:"http://localhost/jame2/api/config"];
    var connection = [CPURLConnection connectionWithRequest:request delegate:self];
}

// CPURLConnection Delegate
- (void)connection:(CPURLConnection)connection didFailWithError:(id)error
{
    console.log(_cmd);
    console.log(error);
    console.log(CPURLConnectionDelegate);
}


- (void)connection:(CPURLConnection)connection didReceiveResponse:(CPHTTPURLResponse)response
{
    console.log(_cmd);
    console.log(CPURLConnectionDelegate);
}

- (void)connection:(CPURLConnection)connection didReceiveData:(CPString)data
{
    console.log(_cmd);
    console.log(data);
    console.log(CPURLConnectionDelegate);
}

- (void)connectionDidFinishLoading:(CPURLConnection)connection
{
    console.log(_cmd);
}

- (CPDictionary)authenticationControllerRequestedUserCredentials:(J2AuthenticationController)authenticationController
{
    return {username: "testuser", password: "testuser"};
}

@end
