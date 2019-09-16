# sapphire-auth
Library for authenticating requests using an OAuth-like signing method.

## Install
```
npm install --save sapphire-auth
```

## API

### Static Properties

#### apiKeyHeaderName
The name of the header that contains the API key.  This header is required for all requests.

#### timestampHeaderName
The name of the header that contains the timestamp for when the request was sent. This header is required for all requests.  The timestamp must be in milliseconds since the Unix epoch.  The request must be received within 1000ms (1 second) of when the request was sent.

#### signatureHeaderName
The name of the header that contains the Sapphire signature.  This header is required for all requests.

#### nonceHeaderName
The name of the header that contains a unique token for each request.  This token can be used to help avoid replay attacks.  While not required, it is strongly recommended.

### Instance Methods

#### generateSignature()
Generates the Sapphire signature that should be added to the headers in a request to Sapphire or response from Sapphire.

##### Parameters
| Name | Type | Description |
|------|------|-------------|
| method | string | The HTTP method used for the request |
| url | string | the URL of the resource being requested.  This does not include the query param string |
| headers | { [ headerName: string ]: string } | the headers being sent with the request |
| params | { [ paramName: string ]: any } | the parameters included in the request.  This includes query string params, URL encoded parameters (as an object), or a JSON body |

#### isExpressRequestValid()
A shorthand for `isMessageValid()` for Express.js apps.

See [isMessageValid()](#ismessagevalid) for more information.

##### Parameters
| Name | Type | Description |
|------|------|-------------|
| req | Request | The Express.js request object. |
| overrides | [object] | Optional.  Any overrides that should be applied to the request object.  This is useful, for example, if you are behind another application that redirects traffic to your Express instance. |
| overrides.protocol | [string] | Optional. The protocol to use when generating the signature. |
| overrides.hostname | [string] | Optional. The hostname to use when generating the signature.

#### isMessageValid()
Validates an HTTP request or response.

Returns true if the message contains a valid signature; false otherwise.

##### Parameters
| Name | Type | Description |
|------|------|-------------|
| method | string | The HTTP method used for the request |
| url | string | the URL of the resource being requested.  This does not include the query param string |
| headers | { [ headerName: string ]: string } | the headers being sent with the request |
| params | { [ paramName: string ]: any } | the parameters included in the request.  This includes query string params, URL encoded parameters (as an object), or a JSON body |
