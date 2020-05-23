import { CustomAuthorizerEvent, CustomAuthorizerResult } from 'aws-lambda'
import 'source-map-support/register'

// import { verify, decode } from 'jsonwebtoken'
import { verify } from 'jsonwebtoken'
import { createLogger } from '../../utils/logger'
// import Axios from 'axios'
// import { Jwt } from '../../auth/Jwt'
import { JwtPayload } from '../../auth/JwtPayload'

const logger = createLogger('auth')

// TODO: Provide a URL that can be used to download a certificate that can be used
// to verify JWT token signature.
// To get this URL you need to go to an Auth0 page -> Show Advanced Settings -> Endpoints -> JSON Web Key Set
// const jwksUrl = ''
const cert = `-----BEGIN CERTIFICATE-----
MIIC+TCCAeGgAwIBAgIJFYkootL4FPpgMA0GCSqGSIb3DQEBCwUAMBoxGDAWBgNV
BAMTD3N1cDk5LmF1dGgwLmNvbTAeFw0yMDA1MjMwOTQ4NDlaFw0zNDAxMzAwOTQ4
NDlaMBoxGDAWBgNVBAMTD3N1cDk5LmF1dGgwLmNvbTCCASIwDQYJKoZIhvcNAQEB
BQADggEPADCCAQoCggEBAL1FJFpNxUGOH29kNajC2ukc6FwninLTQZLkhVkSN/bb
XSfHa6f9fqwNmQCttWujL4YpJnIUUEslES1s1OIelG2T7IcVYGefcVqSWoDOyAgw
7L5Xxs14NcXJXMSo4evmUYVpgILgkzJnt5e28CkhiDlDVRXs2mi5PqzhLEA/0oT2
7PCE6lEiYN0mipra72Rtfgii7NXLTLjUyPhiLrlmcnUhJrlzYIE7m/VVIHrhmCpQ
Q9gg8POIkQmpdp57WxQiPn6D7FexrLo7Px5j0WawBQV2a2DoHOTpuyRbo9DjNt//
T6fUKDC5SvQbygQKEdYz+SZjYgsOqFEDn6VYRupIpFcCAwEAAaNCMEAwDwYDVR0T
AQH/BAUwAwEB/zAdBgNVHQ4EFgQUR2k9wgl2f8qj99z5maMRFtCrdGgwDgYDVR0P
AQH/BAQDAgKEMA0GCSqGSIb3DQEBCwUAA4IBAQArU9mWG3m2W5fFjG+JabE44rwN
vYRawAEGG7NF+Z4xXZ/77Yz9fZ8xXk2B76/Dq7mauGdyR7SLiwvvbkE4nyPEpL23
5/YG/8mUhI/wvzRgHw/CDr+hpx7B6++TILrYbqbug8UCMiI4pT9ouoQ3mjFBMH6w
aI3qH2Crme6OyZcJ5Dgju1K5WmLqWan/pZsKF4o8ov2vtCEswEHgA+jmrIgJHHiM
kEtrjOADcwA+fZve3AovYxqoev4djSRswNT9gP3SFHjbaAQ29fL6liorY4AzUHbt
aDHLo57B3e0LA2dUorJEbmjCdDiZ6cTZF48PLXnKSPyU33dcyZyl+nIWLEtr
-----END CERTIFICATE-----`

export const handler = async (event: CustomAuthorizerEvent): Promise<CustomAuthorizerResult> => {
  logger.info('Authorizing a user', event.authorizationToken)
  try {
    const jwtToken = await verifyToken(event.authorizationToken)
    logger.info('User was authorized', jwtToken)

    return {
      principalId: jwtToken.sub,
      policyDocument: {
        Version: '2012-10-17',
        Statement: [
          {
            Action: 'execute-api:Invoke',
            Effect: 'Allow',
            Resource: '*'
          }
        ]
      }
    }
  } catch (e) {
    logger.error('User not authorized', { error: e.message })

    return {
      principalId: 'user',
      policyDocument: {
        Version: '2012-10-17',
        Statement: [
          {
            Action: 'execute-api:Invoke',
            Effect: 'Deny',
            Resource: '*'
          }
        ]
      }
    }
  }
}

async function verifyToken(authHeader: string): Promise<JwtPayload> {
  const token = getToken(authHeader)
  // const jwt: Jwt = decode(token, { complete: true }) as Jwt

  // Implement token verification
  // You should implement it similarly to how it was implemented for the exercise for the lesson 5
  // You can read more about how to do this here: https://auth0.com/blog/navigating-rs256-and-jwks/
  return  verify(token, cert, { algorithms: ['RS256'] }) as JwtPayload
}

function getToken(authHeader: string): string {
  if (!authHeader) throw new Error('No authentication header')

  if (!authHeader.toLowerCase().startsWith('bearer '))
    throw new Error('Invalid authentication header')

  const split = authHeader.split(' ')
  const token = split[1]

  return token
}
