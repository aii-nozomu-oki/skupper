/*
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package certs

import (
	"testing"

	"gotest.tools/assert"
)

func TestParsePrivateKey(t *testing.T) {
	pkcs1PrivateKey := `-----BEGIN RSA PRIVATE KEY-----
MIIEogIBAAKCAQEAm6Wwo8zXZ35C8ToXvKfq2Ys1ETZQ02w9sHgL4/uoW4iSrLxk
2EPrl4Q22cc2wcn+aE4ljcroPRHfm+e8dq467318tVJ2U15JoRNYpF1LPnsqECxP
who81anGeT4T27D5tHl+eESa2a9cwVPRuRu5dQkPAW7bu/baashQoE4xuaaLfQA6
FDLgpG5g90hW0+kt7gdUn1Ap3qz9kI77PGXbP+8FZiEYynJfgSdb9FboT+3yzfoS
P9+/Hyi3d0ZdmMW7OdnYTtGLEU/ZCCt9Bhp2soFlHqYnLdRqI+2MH4LSuE+FShe4
JauQ23tIW7/SEvIlghmdANVNrJlnTHJyOw5mywIDAQABAoIBAHTfEyXLmCrT+fwc
PNqh04yKJMzJ1iMK8b9iRLtpqd8hS9F8nNRvG6Xn1y/rkEgvHmK/2x7/Lyc8FoWA
mlkbNpHBzjRwuPycnfjfB/5TNz6xSMJgI3uCLA/brXY4kLyzxKwpVjeEfCncrW9V
OvMdyEIDDUtsLH6VOyhXRYM5c8kMA4WTsQoj/ItgLpQ2fOZXTNqG/Zn9aoOpEpbu
vLSVTLVHIW3EE5qdIpwJZOw3WuI0Ev9JtpKdbFkoVmJtelSKQZow5/DDo2sjX8kF
rT9fLSugU/3X04NMUq5dGhgsZCxIuvgeC/voBtDokFsuSSj3zSlQVr+XNDuAazy5
GOkusqECgYEAyOeFX0q94maB+5ZWeryuNQZFYA8QxHFqqCni/Bv4it3lq0vSLFWv
sLE6iO6eQI8olBCjHINkpHOx58cbJPI5Js4CoxqDbLkXzrVWpUPoABtuzOS9KcaI
+6/BxjWJ1Sqg7+GNrBM+CP3Nnk64Alj6q1ih6cJXWJw3mPuJsnlzxzMCgYEAxlTk
v09Qha3cR6QRfmJup7MvYKudxZQceytBgnGqGaHOTao0HWUOcPZhM+ui1OEPrAbX
zv++ykWkp8iJYIfPv/DDtZX2gztfsnIuwZIrEsQoT4JQsZoG/dKc3c5jV6GSCbGd
SMrQe61yZO+VLztxv7hNN/58BeJcLF2kdN/aAgkCgYAfrEBekY32D2sWmtDvcKeW
PHLbfgSKs8a41EGwtUgtvGXk54Mu8iNMm+Q6ikPwsaEYFrdgW2aWdpbpj348COPx
tjC8PgXSMiwKrpQGYfpFag3Bx5365A3cgAzwjqg4LwxIRSrsoev5xumPt6FS3WxH
byW3kKfslFQ/jghbVsJl+QKBgBuqf/ZH5B2hsRa1RlNw+6qdDkDX77w9+vMbh5ng
rS/CKHshAQAQtsD/PXP2rNIxSvReSAByIHUq3dsh2DgE+e/2b/aGosqPn7vOvcL2
1tdZUZ41uXfs2ojRtlwijC0PNsXvZtdeo1J9UXXPDep2yllKJktnTnmrp9vwfB5p
k4mxAoGAflGCaf7m4+MYJFK92asUTYJOtjGKHzcNH3aUCrwlJsTjhTcvtFJsb0p/
p9KQlNfDYieZDtzRJsMPo4BSHSqdndffH3tF/4aczw1R29MjLsDI5Een2CBlKyiC
HjWgeyRF9Lz5fO9ttYG+WFadMY/IKWFMrDjle/PZxDPPOffucFQ=
-----END RSA PRIVATE KEY-----`

	_, err := parsePrivateKey(decodeDataElement([]byte(pkcs1PrivateKey), "certificate"))
	assert.NilError(t, err)

	pkcs8PrivateKey := `-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCt03aIOKrpaKmB
/9DREJLcVcglEZBYWIhh5GoPU9VXZ+V7xGfnlkbZwLKQaqQFNwS/9gWWW8kgL1aP
x8UEsySpElYX1LpUQMXYpP25IVZLfmVHw6AaLYmnDXlkZy63A2pe70i/GyKoblxp
8C80BflxGO3OXSf+T2JuUp3lsSpsaa6b/XbQwyjB3dsm1tgdeBQOyKVh2j9LThad
4/BfIV4vNq+VZ1wBsXeCjmRJVPTin2ZQBputhZAEB2xlbzKlNlxa0TA5PK77aF+E
x1iGqnE08tRt9bbO6UR0jyJEnBgbZuxlMaGBXNsDmEA1EsTiLG91uMmeqx/Bw7eB
E5GlPtzTAgMBAAECggEAUDj1zWyJxGsfP/X2Q2ZowPN+CU2P1pYVa0hlgmloXox+
pp5Abes3C6wZPPladWWs9YLvlTMLIaV3R6gkz0R2OOlTfnAZBmVWaePLjTNLhk/x
IiuwqiQ2ETjwu1u7fY8/+kxowHofhqhYUjQdNN9E/eNJbSIlIQM2JEBQyv72200v
oxWgrbxV6HbZDcx1J5VTPS6ofKs80E/GE37/0mbpOz4OeQI054DLnBPLIiSNPtfH
h0W0rNDuiq/BL8hJR5awASS8LTJY9xqKWfBJIB1A5XNGAqRkOAGYEt/HuGf3zkwJ
WY12oDhLM/T3V7MrgWUgTzu64skpers3cJKh+tIS0QKBgQDEF91M4hxvRDavIfN5
zeiCAyTMLK0rdu+h/MW3SwmFUUzyQWZQq/prlxTX0u7tzFywsT5dE62fQfYMu7RB
dusjchaZq53qgbE8h1Rg6pQpjKBOMMadgYp8hE+cw/yMYOWJB5/OcGCo1zxCkBNU
6/M8diGlC8rqHUP6GFgn6GIBVQKBgQDi7h3/wN6oQGJ7l2t6LHcepNrd5wXCKA4p
2Sg3VwlgfdYoDJ0Rr2sU87Ca0V8b/3vjfF/VfdB2unb5y4olpC4CHXPv3Xs8CqOS
m7gbx/pOeTXwEptlX2Zl2sBAuRSMo/EhxgZJYLl4pE8HrVbCCktmL2lIxy63/OyZ
+xtN/2OFhwKBgGn7r/sm1lF438lmIy75ECp8wn2rw+iS/s9hTAdWAg5RM7JXkJIX
cWCHJpfDhKl3470H/vnVceh6gR6+sJ0VRd9BgV+K9u3RLNbXGc7L2kpenCHGkQJ+
CjhkVpcXAj9o+4ZFXaT47fUzZ3leX2RtpmhOPL70kbZZHO1mDPd8zMOFAoGBAJqk
EaVbVV/qoDIAuakD7Bjh1pQo/m+UxDIYXaN4mFc86VdZYR/QHnSkq9CUpO97Zn1b
ICNoHUsLPlBzN6z2+LNQRtVKZNRBm74oh4nG+PfI+cyjoWmvXSRDsYdpmGtOvN97
BoWyeDGSJpjgsqKASWlVHbYOpfOTU9iKmczJIJS5AoGAJBu4QqVfhO1vu4Siztln
JGLcJwXfmXKpCj2iBMm64oymRpMxTB7sddB7P72C3slXozT7zGC6MkMyA63U7CU1
tkuil5GlDF2v6xdqTMBPPfGQij/nVbBm6wil3QvhmL3Qe6C2mS4XHvwNvUTwmI7J
d2JYLzT609u3VgEu++iv4BM=
-----END PRIVATE KEY-----`

	_, err = parsePrivateKey(decodeDataElement([]byte(pkcs8PrivateKey), "certificate"))
	assert.NilError(t, err)
}
