package publiccerts

import (
	"context"
	legoCert "github.com/go-acme/lego/v4/certificate"
	"github.com/google/uuid"
	"github.com/hashicorp/vault/sdk/logical"
	"github.ibm.com/security-services/secrets-manager-vault-plugins-common/certificate"
	"github.ibm.com/security-services/secrets-manager-vault-plugins-common/secret_backend"
	"github.ibm.com/security-services/secrets-manager-vault-plugins-common/secretentry"
	"github.ibm.com/security-services/secrets-manager-vault-plugins-common/secretentry/policies"
	"gotest.tools/v3/assert"
	"strings"
	"testing"
	"time"
)

const (
	secretName   = "name"
	certificates = "-----BEGIN CERTIFICATE-----\nMIIFgDCCBGigAwIBAgITAPpIgDr4LsgOI6EeXDiBZ/nFczANBgkqhkiG9w0BAQsF\nADBZMQswCQYDVQQGEwJVUzEgMB4GA1UEChMXKFNUQUdJTkcpIExldCdzIEVuY3J5\ncHQxKDAmBgNVBAMTHyhTVEFHSU5HKSBBcnRpZmljaWFsIEFwcmljb3QgUjMwHhcN\nMjEwOTA2MTAwNTAxWhcNMjExMjA1MTAwNTAwWjAvMS0wKwYDVQQDEyRzZWNyZXRz\nLW1hbmFnZXIudGVzdC5hcHBkb21haW4uY2xvdWQwggEiMA0GCSqGSIb3DQEBAQUA\nA4IBDwAwggEKAoIBAQDRN4bYKS/wW3JSHm0CVPcR/OkbmI+fXOP6XYs/Xl5LovFw\nge8gxI37jFIEniR6zuvS4HJuGn70Ya+Yss/SoHXPznuVYfo0IPpHzZUDuCAzhceU\ngOHeJ4H14d4sDuyz/H7Go9Aeq1sPjTkMQ1wfLgzZZnfFJLVwtfrRbTPE+XYyxFBB\ny5zH0VwNxMTSzcfmfPPvFfOPV2pT8lZ6xX0XxJV17v9g2Qlo5Wt9VX9e2o7GzMDv\nPwncgj81S/CzN2zo7+y9C7uDAQJOXpBxNKUSopl2bwFkYt7/CEIz2235VoJEsedI\n+KPZII3mW+69FYy+4MaDUyWiq64DkpoK5HOkt8rbAgMBAAGjggJpMIICZTAOBgNV\nHQ8BAf8EBAMCBaAwHQYDVR0lBBYwFAYIKwYBBQUHAwEGCCsGAQUFBwMCMAwGA1Ud\nEwEB/wQCMAAwHQYDVR0OBBYEFKXI/BlbcKM0/kGLhBKMyn+vYnBVMB8GA1UdIwQY\nMBaAFN5yekjfMcOmUN+fhSPfVzdLXS5lMF0GCCsGAQUFBwEBBFEwTzAlBggrBgEF\nBQcwAYYZaHR0cDovL3N0Zy1yMy5vLmxlbmNyLm9yZzAmBggrBgEFBQcwAoYaaHR0\ncDovL3N0Zy1yMy5pLmxlbmNyLm9yZy8wLwYDVR0RBCgwJoIkc2VjcmV0cy1tYW5h\nZ2VyLnRlc3QuYXBwZG9tYWluLmNsb3VkMEwGA1UdIARFMEMwCAYGZ4EMAQIBMDcG\nCysGAQQBgt8TAQEBMCgwJgYIKwYBBQUHAgEWGmh0dHA6Ly9jcHMubGV0c2VuY3J5\ncHQub3JnMIIBBgYKKwYBBAHWeQIEAgSB9wSB9ADyAHcA3Zk0/KXnJIDJVmh9gTSZ\nCEmySfe1adjHvKs/XMHzbmQAAAF7ushs+wAABAMASDBGAiEA/Poth09OwKLvoysw\n5BR1vW6VuhDERpduTtWXKKooLokCIQDp6qZlu8d1EaNeP+mql9oQRM9jJoyTLNhn\naIkWorr5+gB3ALDMg+Wl+X1rr3wJzChJBIcqx+iLEyxjULfG/SbhbGx3AAABe7rI\nbvQAAAQDAEgwRgIhAOyBcc7if7S/M4kk9puZ4okUaZH3fL/+8SgUzF/ryfGYAiEA\n+1mhCe6ynZAnouAQFt6oDfhwD0JXSowROLnJkGC6QyQwDQYJKoZIhvcNAQELBQAD\nggEBABF5LBBqpWDjvCHeUru/NHrm2BfJvTLbDEYfcT/Woa0NIok5UYS1V84Dns1n\nQKVlTbdMOBL7596CJCaJJNT0q6H4uAzEl+x/LW71puL55b+TN7ZjosOE29K0xFaL\n85YDgXLFnMyf1rZf7Mo+G6kGFJ4yO55AWVXlcCHkMC6UpjaCXZGNA4LPgF4Oom8d\nvnyLd10oLa8XQajNQngJwweaqrbPyOOsq1eEsc3kY06286E4T7akStW+/+KLo/27\nhxl5HDN2Gj5/vf8l80lu13C7fgyUFAYbJnw/02h8AHNv5h0ksFEt2ieLbzVLxvnn\ntmY3WiEwIzkU+M0S6fJwcrfoGec=\n-----END CERTIFICATE-----\n\n-----BEGIN CERTIFICATE-----\nMIIFWzCCA0OgAwIBAgIQTfQrldHumzpMLrM7jRBd1jANBgkqhkiG9w0BAQsFADBm\nMQswCQYDVQQGEwJVUzEzMDEGA1UEChMqKFNUQUdJTkcpIEludGVybmV0IFNlY3Vy\naXR5IFJlc2VhcmNoIEdyb3VwMSIwIAYDVQQDExkoU1RBR0lORykgUHJldGVuZCBQ\nZWFyIFgxMB4XDTIwMDkwNDAwMDAwMFoXDTI1MDkxNTE2MDAwMFowWTELMAkGA1UE\nBhMCVVMxIDAeBgNVBAoTFyhTVEFHSU5HKSBMZXQncyBFbmNyeXB0MSgwJgYDVQQD\nEx8oU1RBR0lORykgQXJ0aWZpY2lhbCBBcHJpY290IFIzMIIBIjANBgkqhkiG9w0B\nAQEFAAOCAQ8AMIIBCgKCAQEAu6TR8+74b46mOE1FUwBrvxzEYLck3iasmKrcQkb+\ngy/z9Jy7QNIAl0B9pVKp4YU76JwxF5DOZZhi7vK7SbCkK6FbHlyU5BiDYIxbbfvO\nL/jVGqdsSjNaJQTg3C3XrJja/HA4WCFEMVoT2wDZm8ABC1N+IQe7Q6FEqc8NwmTS\nnmmRQm4TQvr06DP+zgFK/MNubxWWDSbSKKTH5im5j2fZfg+j/tM1bGaczFWw8/lS\nnukyn5J2L+NJYnclzkXoh9nMFnyPmVbfyDPOc4Y25aTzVoeBKXa/cZ5MM+WddjdL\nbiWvm19f1sYn1aRaAIrkppv7kkn83vcth8XCG39qC2ZvaQIDAQABo4IBEDCCAQww\nDgYDVR0PAQH/BAQDAgGGMB0GA1UdJQQWMBQGCCsGAQUFBwMCBggrBgEFBQcDATAS\nBgNVHRMBAf8ECDAGAQH/AgEAMB0GA1UdDgQWBBTecnpI3zHDplDfn4Uj31c3S10u\nZTAfBgNVHSMEGDAWgBS182Xy/rAKkh/7PH3zRKCsYyXDFDA2BggrBgEFBQcBAQQq\nMCgwJgYIKwYBBQUHMAKGGmh0dHA6Ly9zdGcteDEuaS5sZW5jci5vcmcvMCsGA1Ud\nHwQkMCIwIKAeoByGGmh0dHA6Ly9zdGcteDEuYy5sZW5jci5vcmcvMCIGA1UdIAQb\nMBkwCAYGZ4EMAQIBMA0GCysGAQQBgt8TAQEBMA0GCSqGSIb3DQEBCwUAA4ICAQCN\nDLam9yN0EFxxn/3p+ruWO6n/9goCAM5PT6cC6fkjMs4uas6UGXJjr5j7PoTQf3C1\nvuxiIGRJC6qxV7yc6U0X+w0Mj85sHI5DnQVWN5+D1er7mp13JJA0xbAbHa3Rlczn\ny2Q82XKui8WHuWra0gb2KLpfboYj1Ghgkhr3gau83pC/WQ8HfkwcvSwhIYqTqxoZ\nUq8HIf3M82qS9aKOZE0CEmSyR1zZqQxJUT7emOUapkUN9poJ9zGc+FgRZvdro0XB\nyphWXDaqMYph0DxW/10ig5j4xmmNDjCRmqIKsKoWA52wBTKKXK1na2ty/lW5dhtA\nxkz5rVZFd4sgS4J0O+zm6d5GRkWsNJ4knotGXl8vtS3X40KXeb3A5+/3p0qaD215\nXq8oSNORfB2oI1kQuyEAJ5xvPTdfwRlyRG3lFYodrRg6poUBD/8fNTXMtzydpRgy\nzUQZh/18F6B/iW6cbiRN9r2Hkh05Om+q0/6w0DdZe+8YrNpfhSObr/1eVZbKGMIY\nqKmyZbBNu5ysENIK5MPc14mUeKmFjpN840VR5zunoU52lqpLDua/qIM8idk86xGW\nxx2ml43DO/Ya/tVZVok0mO0TUjzJIfPqyvr455IsIut4RlCR9Iq0EDTve2/ZwCuG\nhSjpTUFGSiQrR2JK2Evp+o6AETUkBCO1aw0PpQBPDQ==\n-----END CERTIFICATE-----\n\n-----BEGIN CERTIFICATE-----\nMIIFVDCCBDygAwIBAgIRAO1dW8lt+99NPs1qSY3Rs8cwDQYJKoZIhvcNAQELBQAw\ncTELMAkGA1UEBhMCVVMxMzAxBgNVBAoTKihTVEFHSU5HKSBJbnRlcm5ldCBTZWN1\ncml0eSBSZXNlYXJjaCBHcm91cDEtMCsGA1UEAxMkKFNUQUdJTkcpIERvY3RvcmVk\nIER1cmlhbiBSb290IENBIFgzMB4XDTIxMDEyMDE5MTQwM1oXDTI0MDkzMDE4MTQw\nM1owZjELMAkGA1UEBhMCVVMxMzAxBgNVBAoTKihTVEFHSU5HKSBJbnRlcm5ldCBT\nZWN1cml0eSBSZXNlYXJjaCBHcm91cDEiMCAGA1UEAxMZKFNUQUdJTkcpIFByZXRl\nbmQgUGVhciBYMTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBALbagEdD\nTa1QgGBWSYkyMhscZXENOBaVRTMX1hceJENgsL0Ma49D3MilI4KS38mtkmdF6cPW\nnL++fgehT0FbRHZgjOEr8UAN4jH6omjrbTD++VZneTsMVaGamQmDdFl5g1gYaigk\nkmx8OiCO68a4QXg4wSyn6iDipKP8utsE+x1E28SA75HOYqpdrk4HGxuULvlr03wZ\nGTIf/oRt2/c+dYmDoaJhge+GOrLAEQByO7+8+vzOwpNAPEx6LW+crEEZ7eBXih6V\nP19sTGy3yfqK5tPtTdXXCOQMKAp+gCj/VByhmIr+0iNDC540gtvV303WpcbwnkkL\nYC0Ft2cYUyHtkstOfRcRO+K2cZozoSwVPyB8/J9RpcRK3jgnX9lujfwA/pAbP0J2\nUPQFxmWFRQnFjaq6rkqbNEBgLy+kFL1NEsRbvFbKrRi5bYy2lNms2NJPZvdNQbT/\n2dBZKmJqxHkxCuOQFjhJQNeO+Njm1Z1iATS/3rts2yZlqXKsxQUzN6vNbD8KnXRM\nEeOXUYvbV4lqfCf8mS14WEbSiMy87GB5S9ucSV1XUrlTG5UGcMSZOBcEUpisRPEm\nQWUOTWIoDQ5FOia/GI+Ki523r2ruEmbmG37EBSBXdxIdndqrjy+QVAmCebyDx9eV\nEGOIpn26bW5LKerumJxa/CFBaKi4bRvmdJRLAgMBAAGjgfEwge4wDgYDVR0PAQH/\nBAQDAgEGMA8GA1UdEwEB/wQFMAMBAf8wHQYDVR0OBBYEFLXzZfL+sAqSH/s8ffNE\noKxjJcMUMB8GA1UdIwQYMBaAFAhX2onHolN5DE/d4JCPdLriJ3NEMDgGCCsGAQUF\nBwEBBCwwKjAoBggrBgEFBQcwAoYcaHR0cDovL3N0Zy1kc3QzLmkubGVuY3Iub3Jn\nLzAtBgNVHR8EJjAkMCKgIKAehhxodHRwOi8vc3RnLWRzdDMuYy5sZW5jci5vcmcv\nMCIGA1UdIAQbMBkwCAYGZ4EMAQIBMA0GCysGAQQBgt8TAQEBMA0GCSqGSIb3DQEB\nCwUAA4IBAQB7tR8B0eIQSS6MhP5kuvGth+dN02DsIhr0yJtk2ehIcPIqSxRRmHGl\n4u2c3QlvEpeRDp2w7eQdRTlI/WnNhY4JOofpMf2zwABgBWtAu0VooQcZZTpQruig\nF/z6xYkBk3UHkjeqxzMN3d1EqGusxJoqgdTouZ5X5QTTIee9nQ3LEhWnRSXDx7Y0\nttR1BGfcdqHopO4IBqAhbkKRjF5zj7OD8cG35omywUbZtOJnftiI0nFcRaxbXo0v\noDfLD0S6+AC2R3tKpqjkNX6/91hrRFglUakyMcZU/xleqbv6+Lr3YD8PsBTub6lI\noZ2lS38fL18Aon458fbc0BPHtenfhKj5\n-----END CERTIFICATE-----\n"
	intermediate = "-----BEGIN CERTIFICATE-----\nMIIFWzCCA0OgAwIBAgIQTfQrldHumzpMLrM7jRBd1jANBgkqhkiG9w0BAQsFADBm\nMQswCQYDVQQGEwJVUzEzMDEGA1UEChMqKFNUQUdJTkcpIEludGVybmV0IFNlY3Vy\naXR5IFJlc2VhcmNoIEdyb3VwMSIwIAYDVQQDExkoU1RBR0lORykgUHJldGVuZCBQ\nZWFyIFgxMB4XDTIwMDkwNDAwMDAwMFoXDTI1MDkxNTE2MDAwMFowWTELMAkGA1UE\nBhMCVVMxIDAeBgNVBAoTFyhTVEFHSU5HKSBMZXQncyBFbmNyeXB0MSgwJgYDVQQD\nEx8oU1RBR0lORykgQXJ0aWZpY2lhbCBBcHJpY290IFIzMIIBIjANBgkqhkiG9w0B\nAQEFAAOCAQ8AMIIBCgKCAQEAu6TR8+74b46mOE1FUwBrvxzEYLck3iasmKrcQkb+\ngy/z9Jy7QNIAl0B9pVKp4YU76JwxF5DOZZhi7vK7SbCkK6FbHlyU5BiDYIxbbfvO\nL/jVGqdsSjNaJQTg3C3XrJja/HA4WCFEMVoT2wDZm8ABC1N+IQe7Q6FEqc8NwmTS\nnmmRQm4TQvr06DP+zgFK/MNubxWWDSbSKKTH5im5j2fZfg+j/tM1bGaczFWw8/lS\nnukyn5J2L+NJYnclzkXoh9nMFnyPmVbfyDPOc4Y25aTzVoeBKXa/cZ5MM+WddjdL\nbiWvm19f1sYn1aRaAIrkppv7kkn83vcth8XCG39qC2ZvaQIDAQABo4IBEDCCAQww\nDgYDVR0PAQH/BAQDAgGGMB0GA1UdJQQWMBQGCCsGAQUFBwMCBggrBgEFBQcDATAS\nBgNVHRMBAf8ECDAGAQH/AgEAMB0GA1UdDgQWBBTecnpI3zHDplDfn4Uj31c3S10u\nZTAfBgNVHSMEGDAWgBS182Xy/rAKkh/7PH3zRKCsYyXDFDA2BggrBgEFBQcBAQQq\nMCgwJgYIKwYBBQUHMAKGGmh0dHA6Ly9zdGcteDEuaS5sZW5jci5vcmcvMCsGA1Ud\nHwQkMCIwIKAeoByGGmh0dHA6Ly9zdGcteDEuYy5sZW5jci5vcmcvMCIGA1UdIAQb\nMBkwCAYGZ4EMAQIBMA0GCysGAQQBgt8TAQEBMA0GCSqGSIb3DQEBCwUAA4ICAQCN\nDLam9yN0EFxxn/3p+ruWO6n/9goCAM5PT6cC6fkjMs4uas6UGXJjr5j7PoTQf3C1\nvuxiIGRJC6qxV7yc6U0X+w0Mj85sHI5DnQVWN5+D1er7mp13JJA0xbAbHa3Rlczn\ny2Q82XKui8WHuWra0gb2KLpfboYj1Ghgkhr3gau83pC/WQ8HfkwcvSwhIYqTqxoZ\nUq8HIf3M82qS9aKOZE0CEmSyR1zZqQxJUT7emOUapkUN9poJ9zGc+FgRZvdro0XB\nyphWXDaqMYph0DxW/10ig5j4xmmNDjCRmqIKsKoWA52wBTKKXK1na2ty/lW5dhtA\nxkz5rVZFd4sgS4J0O+zm6d5GRkWsNJ4knotGXl8vtS3X40KXeb3A5+/3p0qaD215\nXq8oSNORfB2oI1kQuyEAJ5xvPTdfwRlyRG3lFYodrRg6poUBD/8fNTXMtzydpRgy\nzUQZh/18F6B/iW6cbiRN9r2Hkh05Om+q0/6w0DdZe+8YrNpfhSObr/1eVZbKGMIY\nqKmyZbBNu5ysENIK5MPc14mUeKmFjpN840VR5zunoU52lqpLDua/qIM8idk86xGW\nxx2ml43DO/Ya/tVZVok0mO0TUjzJIfPqyvr455IsIut4RlCR9Iq0EDTve2/ZwCuG\nhSjpTUFGSiQrR2JK2Evp+o6AETUkBCO1aw0PpQBPDQ==\n-----END CERTIFICATE-----\n\n-----BEGIN CERTIFICATE-----\nMIIFVDCCBDygAwIBAgIRAO1dW8lt+99NPs1qSY3Rs8cwDQYJKoZIhvcNAQELBQAw\ncTELMAkGA1UEBhMCVVMxMzAxBgNVBAoTKihTVEFHSU5HKSBJbnRlcm5ldCBTZWN1\ncml0eSBSZXNlYXJjaCBHcm91cDEtMCsGA1UEAxMkKFNUQUdJTkcpIERvY3RvcmVk\nIER1cmlhbiBSb290IENBIFgzMB4XDTIxMDEyMDE5MTQwM1oXDTI0MDkzMDE4MTQw\nM1owZjELMAkGA1UEBhMCVVMxMzAxBgNVBAoTKihTVEFHSU5HKSBJbnRlcm5ldCBT\nZWN1cml0eSBSZXNlYXJjaCBHcm91cDEiMCAGA1UEAxMZKFNUQUdJTkcpIFByZXRl\nbmQgUGVhciBYMTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBALbagEdD\nTa1QgGBWSYkyMhscZXENOBaVRTMX1hceJENgsL0Ma49D3MilI4KS38mtkmdF6cPW\nnL++fgehT0FbRHZgjOEr8UAN4jH6omjrbTD++VZneTsMVaGamQmDdFl5g1gYaigk\nkmx8OiCO68a4QXg4wSyn6iDipKP8utsE+x1E28SA75HOYqpdrk4HGxuULvlr03wZ\nGTIf/oRt2/c+dYmDoaJhge+GOrLAEQByO7+8+vzOwpNAPEx6LW+crEEZ7eBXih6V\nP19sTGy3yfqK5tPtTdXXCOQMKAp+gCj/VByhmIr+0iNDC540gtvV303WpcbwnkkL\nYC0Ft2cYUyHtkstOfRcRO+K2cZozoSwVPyB8/J9RpcRK3jgnX9lujfwA/pAbP0J2\nUPQFxmWFRQnFjaq6rkqbNEBgLy+kFL1NEsRbvFbKrRi5bYy2lNms2NJPZvdNQbT/\n2dBZKmJqxHkxCuOQFjhJQNeO+Njm1Z1iATS/3rts2yZlqXKsxQUzN6vNbD8KnXRM\nEeOXUYvbV4lqfCf8mS14WEbSiMy87GB5S9ucSV1XUrlTG5UGcMSZOBcEUpisRPEm\nQWUOTWIoDQ5FOia/GI+Ki523r2ruEmbmG37EBSBXdxIdndqrjy+QVAmCebyDx9eV\nEGOIpn26bW5LKerumJxa/CFBaKi4bRvmdJRLAgMBAAGjgfEwge4wDgYDVR0PAQH/\nBAQDAgEGMA8GA1UdEwEB/wQFMAMBAf8wHQYDVR0OBBYEFLXzZfL+sAqSH/s8ffNE\noKxjJcMUMB8GA1UdIwQYMBaAFAhX2onHolN5DE/d4JCPdLriJ3NEMDgGCCsGAQUF\nBwEBBCwwKjAoBggrBgEFBQcwAoYcaHR0cDovL3N0Zy1kc3QzLmkubGVuY3Iub3Jn\nLzAtBgNVHR8EJjAkMCKgIKAehhxodHRwOi8vc3RnLWRzdDMuYy5sZW5jci5vcmcv\nMCIGA1UdIAQbMBkwCAYGZ4EMAQIBMA0GCysGAQQBgt8TAQEBMA0GCSqGSIb3DQEB\nCwUAA4IBAQB7tR8B0eIQSS6MhP5kuvGth+dN02DsIhr0yJtk2ehIcPIqSxRRmHGl\n4u2c3QlvEpeRDp2w7eQdRTlI/WnNhY4JOofpMf2zwABgBWtAu0VooQcZZTpQruig\nF/z6xYkBk3UHkjeqxzMN3d1EqGusxJoqgdTouZ5X5QTTIee9nQ3LEhWnRSXDx7Y0\nttR1BGfcdqHopO4IBqAhbkKRjF5zj7OD8cG35omywUbZtOJnftiI0nFcRaxbXo0v\noDfLD0S6+AC2R3tKpqjkNX6/91hrRFglUakyMcZU/xleqbv6+Lr3YD8PsBTub6lI\noZ2lS38fL18Aon458fbc0BPHtenfhKj5\n-----END CERTIFICATE-----\n"
	privKey      = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA0TeG2Ckv8FtyUh5tAlT3EfzpG5iPn1zj+l2LP15eS6LxcIHv\nIMSN+4xSBJ4kes7r0uBybhp+9GGvmLLP0qB1z857lWH6NCD6R82VA7ggM4XHlIDh\n3ieB9eHeLA7ss/x+xqPQHqtbD405DENcHy4M2WZ3xSS1cLX60W0zxPl2MsRQQcuc\nx9FcDcTE0s3H5nzz7xXzj1dqU/JWesV9F8SVde7/YNkJaOVrfVV/XtqOxszA7z8J\n3II/NUvwszds6O/svQu7gwECTl6QcTSlEqKZdm8BZGLe/whCM9tt+VaCRLHnSPij\n2SCN5lvuvRWMvuDGg1MloquuA5KaCuRzpLfK2wIDAQABAoIBADBEr0ePuQ+rCWUI\nv/2ZvKbZwq4rNHd/5tkMW+Py0a6BmVJrp8/XiSpP5VxLX/81XhL41W2xjziykOCZ\n4HinrIaVDM4aHK+KLDQEqiyBfmxkoPcSBQpL8x/XTHq9tr6PsnABuzJYNloQKuk5\nYTeQWEaP7XH+Vh363jMTDq6TH0H2vgL5HHSU1UrCjWDHAH6v+hdfPrx6Wm88449A\n757gLY2JuqPvkN+as7hi2UELntOQDa1cSlnJGCRqpUpVWb1v0SNcZ8/7fApsTRJG\nqDpyqi3N7YhtLCtd8F5Uzo08ML5cPWwruECJK+UfCe3KcpTntmGimDIrWYO1Vxof\nLnS8ZwECgYEA6UpcO54KWndlrr5ldI3UBr2OBM1b1SfgmyFMDKK78SpBrUpK5tMc\n/lwjzsKTZAxTBWDv1etBImfQBr/OQ6ZAsgXyTzwtJFmhSnqGThJo2BkdAkKq08SC\n6HoUSOF2Xndck/h+6qnQIM6m2PAKn5VQjtkRGyaZTcsKBUcJsMehhPMCgYEA5ZU/\ntf5pYPNtk7h/mfRrSKIRLN27QzK3vu+/WbRtehLvjXRicFjny1mzbEciDkw9B7jx\nV1PNrTv2vOWvhqxxwmHOvIYpieCNMnuhKKiKZ7BZY8x5qL9chFHvj8sHdFn7L/R8\nW4RaPSwcUF5xDJj/6Gd2+IZOUVZaEwNo1pKtPHkCgYEAu3o5suNn2JnZClwR9l/A\nA4azqeJKqXr5glF45zKkLMPTsephVSxVQYhUcmVlw2IwGcN0GgqL9pVM1Q+xOCZU\nGXyz5L8sW+j3uH3MjtM2lGtiJ53h4Hss5Jyuzn75/CKaMIPjorvC+Yp5BR+queJp\nsdJ5b8NOMfk4XVNgU0Oq5scCgYA5zR3BQFBfrGoGKwlVRYhNPSB930VqYbaJR+sx\nNo/pkCLnxkmSZ4/UTr0xoacdWmxzKUj554t89f/lBx7uFTR+8AkQxeZnZDWoZB/r\nEKPn/ypCShTHO4abedWKql8yGAV5yWAV2nitthFa2qwzs8GaTZJSd9339HmxF8ap\nXzxmYQKBgCKfWBiZL4x2KEipo5nvu2OBtOxbeXEwp2pXc3ewhOFJr4tI1h19QYGj\n9w4TDwC1da4Z00foRREuRWN9902zkjkBPdb9mMJPKWiRuuStD51BA4YEdCQwe8Hk\n917NTMlTgb4cW7mokWJyqv5uKIDUAOnAdl40zt2VgdofYvgL0X8W\n-----END RSA PRIVATE KEY-----\n"
	createdBy    = "CreatedBy"
	/*  "algorithm": "SHA256-RSA",
	    "alt_names": [
	      "secrets-manager.test.appdomain.cloud"
	    ],
	    "common_name": "secrets-manager.test.appdomain.cloud",
	    "created_by": "iam-ServiceId-8d00e792-cbe4-4bca-84c7-5c047c7e7e7e",
	    "creation_date": "2021-09-06T11:03:54Z",
	    "crn": "crn:v1:staging:public:secrets-manager:us-south:a/791f5fb10986423e97aa8512f18b7e65:64be543a-3901-4f54-9d60-854382b21f29:secret:6bfe1c41-ae6f-5fb2-82ae-f0226ddaa369",
	    "description": "desc",
	    "expiration_date": "2021-12-05T10:05:00Z",
	    "id": "6bfe1c41-ae6f-5fb2-82ae-f0226ddaa369",
	    "intermediate_included": true,
	    "issuance_info": {
	      "auto_rotated": true,
	      "bundle_certs": true,
	      "ca": "myLE",
	      "dns": "myCIS",
	      "error_code": "secrets-manager.Error07012",
	      "error_message": "Certificate authority configuration with name 'myLE' was not found",
	      "ordered_on": "2021-09-06T11:10:00Z",
	      "state": 3,
	      "state_description": "Deactivated"
	    },
	    "issuer": "US (STAGING) Let's Encrypt (STAGING) Artificial Apricot R3",
	    "key_algorithm": "RSA2048",
	    "labels": [],
	    "last_update_date": "2021-09-06T11:05:03Z",
	    "name": "mytest3",
	    "private_key_included": true,
	    "secret_data": {
	      "certificate": "-----BEGIN CERTIFICATE-----\nMIIFgDCCBGigAwIBAgITAPpIgDr4LsgOI6EeXDiBZ/nFczANBgkqhkiG9w0BAQsF\nADBZMQswCQYDVQQGEwJVUzEgMB4GA1UEChMXKFNUQUdJTkcpIExldCdzIEVuY3J5\ncHQxKDAmBgNVBAMTHyhTVEFHSU5HKSBBcnRpZmljaWFsIEFwcmljb3QgUjMwHhcN\nMjEwOTA2MTAwNTAxWhcNMjExMjA1MTAwNTAwWjAvMS0wKwYDVQQDEyRzZWNyZXRz\nLW1hbmFnZXIudGVzdC5hcHBkb21haW4uY2xvdWQwggEiMA0GCSqGSIb3DQEBAQUA\nA4IBDwAwggEKAoIBAQDRN4bYKS/wW3JSHm0CVPcR/OkbmI+fXOP6XYs/Xl5LovFw\nge8gxI37jFIEniR6zuvS4HJuGn70Ya+Yss/SoHXPznuVYfo0IPpHzZUDuCAzhceU\ngOHeJ4H14d4sDuyz/H7Go9Aeq1sPjTkMQ1wfLgzZZnfFJLVwtfrRbTPE+XYyxFBB\ny5zH0VwNxMTSzcfmfPPvFfOPV2pT8lZ6xX0XxJV17v9g2Qlo5Wt9VX9e2o7GzMDv\nPwncgj81S/CzN2zo7+y9C7uDAQJOXpBxNKUSopl2bwFkYt7/CEIz2235VoJEsedI\n+KPZII3mW+69FYy+4MaDUyWiq64DkpoK5HOkt8rbAgMBAAGjggJpMIICZTAOBgNV\nHQ8BAf8EBAMCBaAwHQYDVR0lBBYwFAYIKwYBBQUHAwEGCCsGAQUFBwMCMAwGA1Ud\nEwEB/wQCMAAwHQYDVR0OBBYEFKXI/BlbcKM0/kGLhBKMyn+vYnBVMB8GA1UdIwQY\nMBaAFN5yekjfMcOmUN+fhSPfVzdLXS5lMF0GCCsGAQUFBwEBBFEwTzAlBggrBgEF\nBQcwAYYZaHR0cDovL3N0Zy1yMy5vLmxlbmNyLm9yZzAmBggrBgEFBQcwAoYaaHR0\ncDovL3N0Zy1yMy5pLmxlbmNyLm9yZy8wLwYDVR0RBCgwJoIkc2VjcmV0cy1tYW5h\nZ2VyLnRlc3QuYXBwZG9tYWluLmNsb3VkMEwGA1UdIARFMEMwCAYGZ4EMAQIBMDcG\nCysGAQQBgt8TAQEBMCgwJgYIKwYBBQUHAgEWGmh0dHA6Ly9jcHMubGV0c2VuY3J5\ncHQub3JnMIIBBgYKKwYBBAHWeQIEAgSB9wSB9ADyAHcA3Zk0/KXnJIDJVmh9gTSZ\nCEmySfe1adjHvKs/XMHzbmQAAAF7ushs+wAABAMASDBGAiEA/Poth09OwKLvoysw\n5BR1vW6VuhDERpduTtWXKKooLokCIQDp6qZlu8d1EaNeP+mql9oQRM9jJoyTLNhn\naIkWorr5+gB3ALDMg+Wl+X1rr3wJzChJBIcqx+iLEyxjULfG/SbhbGx3AAABe7rI\nbvQAAAQDAEgwRgIhAOyBcc7if7S/M4kk9puZ4okUaZH3fL/+8SgUzF/ryfGYAiEA\n+1mhCe6ynZAnouAQFt6oDfhwD0JXSowROLnJkGC6QyQwDQYJKoZIhvcNAQELBQAD\nggEBABF5LBBqpWDjvCHeUru/NHrm2BfJvTLbDEYfcT/Woa0NIok5UYS1V84Dns1n\nQKVlTbdMOBL7596CJCaJJNT0q6H4uAzEl+x/LW71puL55b+TN7ZjosOE29K0xFaL\n85YDgXLFnMyf1rZf7Mo+G6kGFJ4yO55AWVXlcCHkMC6UpjaCXZGNA4LPgF4Oom8d\nvnyLd10oLa8XQajNQngJwweaqrbPyOOsq1eEsc3kY06286E4T7akStW+/+KLo/27\nhxl5HDN2Gj5/vf8l80lu13C7fgyUFAYbJnw/02h8AHNv5h0ksFEt2ieLbzVLxvnn\ntmY3WiEwIzkU+M0S6fJwcrfoGec=\n-----END CERTIFICATE-----\n\n-----BEGIN CERTIFICATE-----\nMIIFWzCCA0OgAwIBAgIQTfQrldHumzpMLrM7jRBd1jANBgkqhkiG9w0BAQsFADBm\nMQswCQYDVQQGEwJVUzEzMDEGA1UEChMqKFNUQUdJTkcpIEludGVybmV0IFNlY3Vy\naXR5IFJlc2VhcmNoIEdyb3VwMSIwIAYDVQQDExkoU1RBR0lORykgUHJldGVuZCBQ\nZWFyIFgxMB4XDTIwMDkwNDAwMDAwMFoXDTI1MDkxNTE2MDAwMFowWTELMAkGA1UE\nBhMCVVMxIDAeBgNVBAoTFyhTVEFHSU5HKSBMZXQncyBFbmNyeXB0MSgwJgYDVQQD\nEx8oU1RBR0lORykgQXJ0aWZpY2lhbCBBcHJpY290IFIzMIIBIjANBgkqhkiG9w0B\nAQEFAAOCAQ8AMIIBCgKCAQEAu6TR8+74b46mOE1FUwBrvxzEYLck3iasmKrcQkb+\ngy/z9Jy7QNIAl0B9pVKp4YU76JwxF5DOZZhi7vK7SbCkK6FbHlyU5BiDYIxbbfvO\nL/jVGqdsSjNaJQTg3C3XrJja/HA4WCFEMVoT2wDZm8ABC1N+IQe7Q6FEqc8NwmTS\nnmmRQm4TQvr06DP+zgFK/MNubxWWDSbSKKTH5im5j2fZfg+j/tM1bGaczFWw8/lS\nnukyn5J2L+NJYnclzkXoh9nMFnyPmVbfyDPOc4Y25aTzVoeBKXa/cZ5MM+WddjdL\nbiWvm19f1sYn1aRaAIrkppv7kkn83vcth8XCG39qC2ZvaQIDAQABo4IBEDCCAQww\nDgYDVR0PAQH/BAQDAgGGMB0GA1UdJQQWMBQGCCsGAQUFBwMCBggrBgEFBQcDATAS\nBgNVHRMBAf8ECDAGAQH/AgEAMB0GA1UdDgQWBBTecnpI3zHDplDfn4Uj31c3S10u\nZTAfBgNVHSMEGDAWgBS182Xy/rAKkh/7PH3zRKCsYyXDFDA2BggrBgEFBQcBAQQq\nMCgwJgYIKwYBBQUHMAKGGmh0dHA6Ly9zdGcteDEuaS5sZW5jci5vcmcvMCsGA1Ud\nHwQkMCIwIKAeoByGGmh0dHA6Ly9zdGcteDEuYy5sZW5jci5vcmcvMCIGA1UdIAQb\nMBkwCAYGZ4EMAQIBMA0GCysGAQQBgt8TAQEBMA0GCSqGSIb3DQEBCwUAA4ICAQCN\nDLam9yN0EFxxn/3p+ruWO6n/9goCAM5PT6cC6fkjMs4uas6UGXJjr5j7PoTQf3C1\nvuxiIGRJC6qxV7yc6U0X+w0Mj85sHI5DnQVWN5+D1er7mp13JJA0xbAbHa3Rlczn\ny2Q82XKui8WHuWra0gb2KLpfboYj1Ghgkhr3gau83pC/WQ8HfkwcvSwhIYqTqxoZ\nUq8HIf3M82qS9aKOZE0CEmSyR1zZqQxJUT7emOUapkUN9poJ9zGc+FgRZvdro0XB\nyphWXDaqMYph0DxW/10ig5j4xmmNDjCRmqIKsKoWA52wBTKKXK1na2ty/lW5dhtA\nxkz5rVZFd4sgS4J0O+zm6d5GRkWsNJ4knotGXl8vtS3X40KXeb3A5+/3p0qaD215\nXq8oSNORfB2oI1kQuyEAJ5xvPTdfwRlyRG3lFYodrRg6poUBD/8fNTXMtzydpRgy\nzUQZh/18F6B/iW6cbiRN9r2Hkh05Om+q0/6w0DdZe+8YrNpfhSObr/1eVZbKGMIY\nqKmyZbBNu5ysENIK5MPc14mUeKmFjpN840VR5zunoU52lqpLDua/qIM8idk86xGW\nxx2ml43DO/Ya/tVZVok0mO0TUjzJIfPqyvr455IsIut4RlCR9Iq0EDTve2/ZwCuG\nhSjpTUFGSiQrR2JK2Evp+o6AETUkBCO1aw0PpQBPDQ==\n-----END CERTIFICATE-----\n\n-----BEGIN CERTIFICATE-----\nMIIFVDCCBDygAwIBAgIRAO1dW8lt+99NPs1qSY3Rs8cwDQYJKoZIhvcNAQELBQAw\ncTELMAkGA1UEBhMCVVMxMzAxBgNVBAoTKihTVEFHSU5HKSBJbnRlcm5ldCBTZWN1\ncml0eSBSZXNlYXJjaCBHcm91cDEtMCsGA1UEAxMkKFNUQUdJTkcpIERvY3RvcmVk\nIER1cmlhbiBSb290IENBIFgzMB4XDTIxMDEyMDE5MTQwM1oXDTI0MDkzMDE4MTQw\nM1owZjELMAkGA1UEBhMCVVMxMzAxBgNVBAoTKihTVEFHSU5HKSBJbnRlcm5ldCBT\nZWN1cml0eSBSZXNlYXJjaCBHcm91cDEiMCAGA1UEAxMZKFNUQUdJTkcpIFByZXRl\nbmQgUGVhciBYMTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBALbagEdD\nTa1QgGBWSYkyMhscZXENOBaVRTMX1hceJENgsL0Ma49D3MilI4KS38mtkmdF6cPW\nnL++fgehT0FbRHZgjOEr8UAN4jH6omjrbTD++VZneTsMVaGamQmDdFl5g1gYaigk\nkmx8OiCO68a4QXg4wSyn6iDipKP8utsE+x1E28SA75HOYqpdrk4HGxuULvlr03wZ\nGTIf/oRt2/c+dYmDoaJhge+GOrLAEQByO7+8+vzOwpNAPEx6LW+crEEZ7eBXih6V\nP19sTGy3yfqK5tPtTdXXCOQMKAp+gCj/VByhmIr+0iNDC540gtvV303WpcbwnkkL\nYC0Ft2cYUyHtkstOfRcRO+K2cZozoSwVPyB8/J9RpcRK3jgnX9lujfwA/pAbP0J2\nUPQFxmWFRQnFjaq6rkqbNEBgLy+kFL1NEsRbvFbKrRi5bYy2lNms2NJPZvdNQbT/\n2dBZKmJqxHkxCuOQFjhJQNeO+Njm1Z1iATS/3rts2yZlqXKsxQUzN6vNbD8KnXRM\nEeOXUYvbV4lqfCf8mS14WEbSiMy87GB5S9ucSV1XUrlTG5UGcMSZOBcEUpisRPEm\nQWUOTWIoDQ5FOia/GI+Ki523r2ruEmbmG37EBSBXdxIdndqrjy+QVAmCebyDx9eV\nEGOIpn26bW5LKerumJxa/CFBaKi4bRvmdJRLAgMBAAGjgfEwge4wDgYDVR0PAQH/\nBAQDAgEGMA8GA1UdEwEB/wQFMAMBAf8wHQYDVR0OBBYEFLXzZfL+sAqSH/s8ffNE\noKxjJcMUMB8GA1UdIwQYMBaAFAhX2onHolN5DE/d4JCPdLriJ3NEMDgGCCsGAQUF\nBwEBBCwwKjAoBggrBgEFBQcwAoYcaHR0cDovL3N0Zy1kc3QzLmkubGVuY3Iub3Jn\nLzAtBgNVHR8EJjAkMCKgIKAehhxodHRwOi8vc3RnLWRzdDMuYy5sZW5jci5vcmcv\nMCIGA1UdIAQbMBkwCAYGZ4EMAQIBMA0GCysGAQQBgt8TAQEBMA0GCSqGSIb3DQEB\nCwUAA4IBAQB7tR8B0eIQSS6MhP5kuvGth+dN02DsIhr0yJtk2ehIcPIqSxRRmHGl\n4u2c3QlvEpeRDp2w7eQdRTlI/WnNhY4JOofpMf2zwABgBWtAu0VooQcZZTpQruig\nF/z6xYkBk3UHkjeqxzMN3d1EqGusxJoqgdTouZ5X5QTTIee9nQ3LEhWnRSXDx7Y0\nttR1BGfcdqHopO4IBqAhbkKRjF5zj7OD8cG35omywUbZtOJnftiI0nFcRaxbXo0v\noDfLD0S6+AC2R3tKpqjkNX6/91hrRFglUakyMcZU/xleqbv6+Lr3YD8PsBTub6lI\noZ2lS38fL18Aon458fbc0BPHtenfhKj5\n-----END CERTIFICATE-----\n",
	      "intermediate": "\n-----BEGIN CERTIFICATE-----\nMIIFWzCCA0OgAwIBAgIQTfQrldHumzpMLrM7jRBd1jANBgkqhkiG9w0BAQsFADBm\nMQswCQYDVQQGEwJVUzEzMDEGA1UEChMqKFNUQUdJTkcpIEludGVybmV0IFNlY3Vy\naXR5IFJlc2VhcmNoIEdyb3VwMSIwIAYDVQQDExkoU1RBR0lORykgUHJldGVuZCBQ\nZWFyIFgxMB4XDTIwMDkwNDAwMDAwMFoXDTI1MDkxNTE2MDAwMFowWTELMAkGA1UE\nBhMCVVMxIDAeBgNVBAoTFyhTVEFHSU5HKSBMZXQncyBFbmNyeXB0MSgwJgYDVQQD\nEx8oU1RBR0lORykgQXJ0aWZpY2lhbCBBcHJpY290IFIzMIIBIjANBgkqhkiG9w0B\nAQEFAAOCAQ8AMIIBCgKCAQEAu6TR8+74b46mOE1FUwBrvxzEYLck3iasmKrcQkb+\ngy/z9Jy7QNIAl0B9pVKp4YU76JwxF5DOZZhi7vK7SbCkK6FbHlyU5BiDYIxbbfvO\nL/jVGqdsSjNaJQTg3C3XrJja/HA4WCFEMVoT2wDZm8ABC1N+IQe7Q6FEqc8NwmTS\nnmmRQm4TQvr06DP+zgFK/MNubxWWDSbSKKTH5im5j2fZfg+j/tM1bGaczFWw8/lS\nnukyn5J2L+NJYnclzkXoh9nMFnyPmVbfyDPOc4Y25aTzVoeBKXa/cZ5MM+WddjdL\nbiWvm19f1sYn1aRaAIrkppv7kkn83vcth8XCG39qC2ZvaQIDAQABo4IBEDCCAQww\nDgYDVR0PAQH/BAQDAgGGMB0GA1UdJQQWMBQGCCsGAQUFBwMCBggrBgEFBQcDATAS\nBgNVHRMBAf8ECDAGAQH/AgEAMB0GA1UdDgQWBBTecnpI3zHDplDfn4Uj31c3S10u\nZTAfBgNVHSMEGDAWgBS182Xy/rAKkh/7PH3zRKCsYyXDFDA2BggrBgEFBQcBAQQq\nMCgwJgYIKwYBBQUHMAKGGmh0dHA6Ly9zdGcteDEuaS5sZW5jci5vcmcvMCsGA1Ud\nHwQkMCIwIKAeoByGGmh0dHA6Ly9zdGcteDEuYy5sZW5jci5vcmcvMCIGA1UdIAQb\nMBkwCAYGZ4EMAQIBMA0GCysGAQQBgt8TAQEBMA0GCSqGSIb3DQEBCwUAA4ICAQCN\nDLam9yN0EFxxn/3p+ruWO6n/9goCAM5PT6cC6fkjMs4uas6UGXJjr5j7PoTQf3C1\nvuxiIGRJC6qxV7yc6U0X+w0Mj85sHI5DnQVWN5+D1er7mp13JJA0xbAbHa3Rlczn\ny2Q82XKui8WHuWra0gb2KLpfboYj1Ghgkhr3gau83pC/WQ8HfkwcvSwhIYqTqxoZ\nUq8HIf3M82qS9aKOZE0CEmSyR1zZqQxJUT7emOUapkUN9poJ9zGc+FgRZvdro0XB\nyphWXDaqMYph0DxW/10ig5j4xmmNDjCRmqIKsKoWA52wBTKKXK1na2ty/lW5dhtA\nxkz5rVZFd4sgS4J0O+zm6d5GRkWsNJ4knotGXl8vtS3X40KXeb3A5+/3p0qaD215\nXq8oSNORfB2oI1kQuyEAJ5xvPTdfwRlyRG3lFYodrRg6poUBD/8fNTXMtzydpRgy\nzUQZh/18F6B/iW6cbiRN9r2Hkh05Om+q0/6w0DdZe+8YrNpfhSObr/1eVZbKGMIY\nqKmyZbBNu5ysENIK5MPc14mUeKmFjpN840VR5zunoU52lqpLDua/qIM8idk86xGW\nxx2ml43DO/Ya/tVZVok0mO0TUjzJIfPqyvr455IsIut4RlCR9Iq0EDTve2/ZwCuG\nhSjpTUFGSiQrR2JK2Evp+o6AETUkBCO1aw0PpQBPDQ==\n-----END CERTIFICATE-----\n\n-----BEGIN CERTIFICATE-----\nMIIFVDCCBDygAwIBAgIRAO1dW8lt+99NPs1qSY3Rs8cwDQYJKoZIhvcNAQELBQAw\ncTELMAkGA1UEBhMCVVMxMzAxBgNVBAoTKihTVEFHSU5HKSBJbnRlcm5ldCBTZWN1\ncml0eSBSZXNlYXJjaCBHcm91cDEtMCsGA1UEAxMkKFNUQUdJTkcpIERvY3RvcmVk\nIER1cmlhbiBSb290IENBIFgzMB4XDTIxMDEyMDE5MTQwM1oXDTI0MDkzMDE4MTQw\nM1owZjELMAkGA1UEBhMCVVMxMzAxBgNVBAoTKihTVEFHSU5HKSBJbnRlcm5ldCBT\nZWN1cml0eSBSZXNlYXJjaCBHcm91cDEiMCAGA1UEAxMZKFNUQUdJTkcpIFByZXRl\nbmQgUGVhciBYMTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBALbagEdD\nTa1QgGBWSYkyMhscZXENOBaVRTMX1hceJENgsL0Ma49D3MilI4KS38mtkmdF6cPW\nnL++fgehT0FbRHZgjOEr8UAN4jH6omjrbTD++VZneTsMVaGamQmDdFl5g1gYaigk\nkmx8OiCO68a4QXg4wSyn6iDipKP8utsE+x1E28SA75HOYqpdrk4HGxuULvlr03wZ\nGTIf/oRt2/c+dYmDoaJhge+GOrLAEQByO7+8+vzOwpNAPEx6LW+crEEZ7eBXih6V\nP19sTGy3yfqK5tPtTdXXCOQMKAp+gCj/VByhmIr+0iNDC540gtvV303WpcbwnkkL\nYC0Ft2cYUyHtkstOfRcRO+K2cZozoSwVPyB8/J9RpcRK3jgnX9lujfwA/pAbP0J2\nUPQFxmWFRQnFjaq6rkqbNEBgLy+kFL1NEsRbvFbKrRi5bYy2lNms2NJPZvdNQbT/\n2dBZKmJqxHkxCuOQFjhJQNeO+Njm1Z1iATS/3rts2yZlqXKsxQUzN6vNbD8KnXRM\nEeOXUYvbV4lqfCf8mS14WEbSiMy87GB5S9ucSV1XUrlTG5UGcMSZOBcEUpisRPEm\nQWUOTWIoDQ5FOia/GI+Ki523r2ruEmbmG37EBSBXdxIdndqrjy+QVAmCebyDx9eV\nEGOIpn26bW5LKerumJxa/CFBaKi4bRvmdJRLAgMBAAGjgfEwge4wDgYDVR0PAQH/\nBAQDAgEGMA8GA1UdEwEB/wQFMAMBAf8wHQYDVR0OBBYEFLXzZfL+sAqSH/s8ffNE\noKxjJcMUMB8GA1UdIwQYMBaAFAhX2onHolN5DE/d4JCPdLriJ3NEMDgGCCsGAQUF\nBwEBBCwwKjAoBggrBgEFBQcwAoYcaHR0cDovL3N0Zy1kc3QzLmkubGVuY3Iub3Jn\nLzAtBgNVHR8EJjAkMCKgIKAehhxodHRwOi8vc3RnLWRzdDMuYy5sZW5jci5vcmcv\nMCIGA1UdIAQbMBkwCAYGZ4EMAQIBMA0GCysGAQQBgt8TAQEBMA0GCSqGSIb3DQEB\nCwUAA4IBAQB7tR8B0eIQSS6MhP5kuvGth+dN02DsIhr0yJtk2ehIcPIqSxRRmHGl\n4u2c3QlvEpeRDp2w7eQdRTlI/WnNhY4JOofpMf2zwABgBWtAu0VooQcZZTpQruig\nF/z6xYkBk3UHkjeqxzMN3d1EqGusxJoqgdTouZ5X5QTTIee9nQ3LEhWnRSXDx7Y0\nttR1BGfcdqHopO4IBqAhbkKRjF5zj7OD8cG35omywUbZtOJnftiI0nFcRaxbXo0v\noDfLD0S6+AC2R3tKpqjkNX6/91hrRFglUakyMcZU/xleqbv6+Lr3YD8PsBTub6lI\noZ2lS38fL18Aon458fbc0BPHtenfhKj5\n-----END CERTIFICATE-----\n",
	      "private_key": "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA0TeG2Ckv8FtyUh5tAlT3EfzpG5iPn1zj+l2LP15eS6LxcIHv\nIMSN+4xSBJ4kes7r0uBybhp+9GGvmLLP0qB1z857lWH6NCD6R82VA7ggM4XHlIDh\n3ieB9eHeLA7ss/x+xqPQHqtbD405DENcHy4M2WZ3xSS1cLX60W0zxPl2MsRQQcuc\nx9FcDcTE0s3H5nzz7xXzj1dqU/JWesV9F8SVde7/YNkJaOVrfVV/XtqOxszA7z8J\n3II/NUvwszds6O/svQu7gwECTl6QcTSlEqKZdm8BZGLe/whCM9tt+VaCRLHnSPij\n2SCN5lvuvRWMvuDGg1MloquuA5KaCuRzpLfK2wIDAQABAoIBADBEr0ePuQ+rCWUI\nv/2ZvKbZwq4rNHd/5tkMW+Py0a6BmVJrp8/XiSpP5VxLX/81XhL41W2xjziykOCZ\n4HinrIaVDM4aHK+KLDQEqiyBfmxkoPcSBQpL8x/XTHq9tr6PsnABuzJYNloQKuk5\nYTeQWEaP7XH+Vh363jMTDq6TH0H2vgL5HHSU1UrCjWDHAH6v+hdfPrx6Wm88449A\n757gLY2JuqPvkN+as7hi2UELntOQDa1cSlnJGCRqpUpVWb1v0SNcZ8/7fApsTRJG\nqDpyqi3N7YhtLCtd8F5Uzo08ML5cPWwruECJK+UfCe3KcpTntmGimDIrWYO1Vxof\nLnS8ZwECgYEA6UpcO54KWndlrr5ldI3UBr2OBM1b1SfgmyFMDKK78SpBrUpK5tMc\n/lwjzsKTZAxTBWDv1etBImfQBr/OQ6ZAsgXyTzwtJFmhSnqGThJo2BkdAkKq08SC\n6HoUSOF2Xndck/h+6qnQIM6m2PAKn5VQjtkRGyaZTcsKBUcJsMehhPMCgYEA5ZU/\ntf5pYPNtk7h/mfRrSKIRLN27QzK3vu+/WbRtehLvjXRicFjny1mzbEciDkw9B7jx\nV1PNrTv2vOWvhqxxwmHOvIYpieCNMnuhKKiKZ7BZY8x5qL9chFHvj8sHdFn7L/R8\nW4RaPSwcUF5xDJj/6Gd2+IZOUVZaEwNo1pKtPHkCgYEAu3o5suNn2JnZClwR9l/A\nA4azqeJKqXr5glF45zKkLMPTsephVSxVQYhUcmVlw2IwGcN0GgqL9pVM1Q+xOCZU\nGXyz5L8sW+j3uH3MjtM2lGtiJ53h4Hss5Jyuzn75/CKaMIPjorvC+Yp5BR+queJp\nsdJ5b8NOMfk4XVNgU0Oq5scCgYA5zR3BQFBfrGoGKwlVRYhNPSB930VqYbaJR+sx\nNo/pkCLnxkmSZ4/UTr0xoacdWmxzKUj554t89f/lBx7uFTR+8AkQxeZnZDWoZB/r\nEKPn/ypCShTHO4abedWKql8yGAV5yWAV2nitthFa2qwzs8GaTZJSd9339HmxF8ap\nXzxmYQKBgCKfWBiZL4x2KEipo5nvu2OBtOxbeXEwp2pXc3ewhOFJr4tI1h19QYGj\n9w4TDwC1da4Z00foRREuRWN9902zkjkBPdb9mMJPKWiRuuStD51BA4YEdCQwe8Hk\n917NTMlTgb4cW7mokWJyqv5uKIDUAOnAdl40zt2VgdofYvgL0X8W\n-----END RSA PRIVATE KEY-----\n"
	    },
	    "secret_type": "public_cert",
	    "serial_number": "fa:48:80:3a:f8:2e:c8:0e:23:a1:1e:5c:38:81:67:f9:c5:73",
	    "state": 1,
	    "state_description": "Active",
	    "validity": {
	      "not_after": "2021-12-05T10:05:00Z",
	      "not_before": "2021-09-06T10:05:01Z"
	    },
	    "versions": [
	      {
	        "created_by": "iam-ServiceId-8d00e792-cbe4-4bca-84c7-5c047c7e7e7e",
	        "creation_date": "2021-09-06T11:03:57.293971Z",
	        "expiration_date": "2021-12-05T10:03:55Z",
	        "id": "4c77f873-1722-ae77-cfff-6ba1c2025173",
	        "payload_available": true,
	        "serial_number": "fa:97:ab:27:0a:00:98:3f:c6:ed:23:ca:17:dd:24:3b:d7:d8",
	        "validity": {
	          "not_after": "2021-12-05T10:03:55Z",
	          "not_before": "2021-09-06T10:03:56Z"
	        }
	      },
	      {
	        "created_by": "iam-ServiceId-8d00e792-cbe4-4bca-84c7-5c047c7e7e7e",
	        "creation_date": "2021-09-06T11:05:03.328699Z",
	        "expiration_date": "2021-12-05T10:05:00Z",
	        "id": "8212dd57-a34b-d54e-5202-fa0e66aad158",
	        "payload_available": true,
	        "serial_number": "fa:48:80:3a:f8:2e:c8:0e:23:a1:1e:5c:38:81:67:f9:c5:73",
	        "validity": {
	          "not_after": "2021-12-05T10:05:00Z",
	          "not_before": "2021-09-06T10:05:01Z"
	        }
	      }
	    ],
	    "versions_total": 2
	  },
	  "warnings": null
	}
	*/
)

var (
	id        = uuid.New()
	secretId  = id.String()
	secretCrn = strings.Replace(smInstanceCrn, "::", ":secret:", 1) + secretId
)

func Test_orders_Handler(t *testing.T) {
	b, storage = secret_backend.SetupTestBackend(&OrdersBackend{})
	oh := &OrdersHandler{
		runningOrders: make(map[string]WorkItem),
		beforeOrders:  make(map[string]WorkItem),
		parser:        &certificate.CertificateParserImpl{},
	}
	t.Run("saveOrderResultToStorage", func(t *testing.T) {
		certMetadata := certificate.CertificateMetadata{
			IssuanceInfo: map[string]interface{}{secretentry.FieldState: secretentry.StatePreActivation, FieldBundleCert: false},
		}
		//extraData,_ := json.Marshal(certMetadata)
		orderResult := Result{
			workItem: WorkItem{
				requestID:  uuid.UUID{},
				caConfig:   &CAUserConfig{},
				dnsConfig:  &ProviderConfig{},
				keyType:    "RSA2048",
				privateKey: nil,
				csr:        nil,
				domains:    []string{"secrets-manager.test.appdomain.cloud"},
				isBundle:   false,
				secretEntry: &secretentry.SecretEntry{
					ID:             secretId,
					Name:           certName1,
					Description:    certDesc,
					Labels:         []string{},
					ExtraData:      certMetadata,
					Versions:       make([]secretentry.SecretVersion, 1),
					CreatedAt:      time.Now(),
					CreatedBy:      createdBy,
					ExpirationDate: nil,
					TTL:            0,
					Policies: policies.Policies{
						Rotation: &policies.RotationPolicy{
							Rotation: &policies.RotationData{
								RotateKeys: false,
								AutoRotate: true,
							},
							Type: ""}},
					Type:    secretentry.SecretTypePublicCert,
					CRN:     secretCrn,
					GroupID: "",
					State:   secretentry.StatePreActivation,
				},
				storage: storage,
			},
			Error: nil,
			certificate: &legoCert.Resource{
				PrivateKey:        []byte(privKey),
				Certificate:       []byte(certificates),
				IssuerCertificate: []byte(intermediate),
			},
		}
		oh.saveOrderResultToStorage(orderResult)
		//check that we still have 1 version
		//state became Active
		//isBundle => separate certs

		req := &logical.Request{
			Operation: logical.ReadOperation,
			Path:      PathSecrets + secretId + PathMetadata,
			Storage:   storage,
			Data:      make(map[string]interface{}),
			Connection: &logical.Connection{
				RemoteAddr: "0.0.0.0",
			},
		}
		resp, err := b.HandleRequest(context.Background(), req)
		assert.NilError(t, err)
		assert.Equal(t, false, resp.IsError())
		assert.Equal(t, resp.Data[secretentry.FieldSecretType], secretentry.SecretTypePublicCert)
		assert.Equal(t, resp.Data[secretentry.FieldName], certName1)
		assert.Equal(t, resp.Data[secretentry.FieldDescription], certDesc)
		//assert.Equal(t, true, reflect.DeepEqual(resp.Data[secretentry.FieldLabels].([]string), labels))
		//
		//assert.Equal(t, len(resp.Data[secretentry.FieldVersions].([]map[string]interface{})), 0)
		//assert.Equal(t, resp.Data[secretentry.FieldVersionsTotal], 1)
		//
		//assert.Equal(t, resp.Data[secretentry.FieldKeyAlgorithm], keyType)
		//assert.Equal(t, resp.Data[secretentry.FieldCommonName], commonName)
		//assert.Equal(t, true, reflect.DeepEqual(resp.Data[secretentry.FieldAltNames].([]string), altNames))
		//assert.Equal(t, resp.Data[secretentry.FieldStateDescription], secretentry.GetNistStateDescription(secretentry.StatePreActivation))
		//assert.Equal(t, resp.Data[secretentry.FieldCreatedBy], "iam-ServiceId-MOCK")
		//assert.Equal(t, resp.Data[FieldIssuanceInfo].(map[string]interface{})[FieldAutoRotated], false)
		//assert.Equal(t, resp.Data[FieldIssuanceInfo].(map[string]interface{})[FieldBundleCert], false)
		//assert.Equal(t, resp.Data[FieldIssuanceInfo].(map[string]interface{})[FieldCAConfig], caConfig)
		//assert.Equal(t, resp.Data[FieldIssuanceInfo].(map[string]interface{})[FieldDNSConfig], dnsConfig)
		//assert.Equal(t, resp.Data[FieldIssuanceInfo].(map[string]interface{})[secretentry.FieldStateDescription], secretentry.GetNistStateDescription(secretentry.StatePreActivation))
		//
		//assert.Equal(t, resp.Data[policies.PolicyTypeRotation].(map[string]interface{})[policies.FieldAutoRotate], true)
		//assert.Equal(t, resp.Data[policies.PolicyTypeRotation].(map[string]interface{})[policies.FieldRotateKeys], true)

	})
}
