package publiccerts

import (
	"context"
	"errors"
	legoCert "github.com/go-acme/lego/v4/certificate"
	"github.com/google/uuid"
	"github.com/hashicorp/vault/sdk/logical"
	"github.ibm.com/security-services/secrets-manager-vault-plugins-common/certificate/certificate_struct"
	"github.ibm.com/security-services/secrets-manager-vault-plugins-common/logdna"
	"github.ibm.com/security-services/secrets-manager-vault-plugins-common/secret_backend"
	"github.ibm.com/security-services/secrets-manager-vault-plugins-common/secretentry"
	"github.ibm.com/security-services/secrets-manager-vault-plugins-common/secretentry/policies"
	"gotest.tools/v3/assert"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"
)

const (
	currentCert         = "-----BEGIN CERTIFICATE-----\nMIIFgDCCBGigAwIBAgITAPpIgDr4LsgOI6EeXDiBZ/nFczANBgkqhkiG9w0BAQsF\nADBZMQswCQYDVQQGEwJVUzEgMB4GA1UEChMXKFNUQUdJTkcpIExldCdzIEVuY3J5\ncHQxKDAmBgNVBAMTHyhTVEFHSU5HKSBBcnRpZmljaWFsIEFwcmljb3QgUjMwHhcN\nMjEwOTA2MTAwNTAxWhcNMjExMjA1MTAwNTAwWjAvMS0wKwYDVQQDEyRzZWNyZXRz\nLW1hbmFnZXIudGVzdC5hcHBkb21haW4uY2xvdWQwggEiMA0GCSqGSIb3DQEBAQUA\nA4IBDwAwggEKAoIBAQDRN4bYKS/wW3JSHm0CVPcR/OkbmI+fXOP6XYs/Xl5LovFw\nge8gxI37jFIEniR6zuvS4HJuGn70Ya+Yss/SoHXPznuVYfo0IPpHzZUDuCAzhceU\ngOHeJ4H14d4sDuyz/H7Go9Aeq1sPjTkMQ1wfLgzZZnfFJLVwtfrRbTPE+XYyxFBB\ny5zH0VwNxMTSzcfmfPPvFfOPV2pT8lZ6xX0XxJV17v9g2Qlo5Wt9VX9e2o7GzMDv\nPwncgj81S/CzN2zo7+y9C7uDAQJOXpBxNKUSopl2bwFkYt7/CEIz2235VoJEsedI\n+KPZII3mW+69FYy+4MaDUyWiq64DkpoK5HOkt8rbAgMBAAGjggJpMIICZTAOBgNV\nHQ8BAf8EBAMCBaAwHQYDVR0lBBYwFAYIKwYBBQUHAwEGCCsGAQUFBwMCMAwGA1Ud\nEwEB/wQCMAAwHQYDVR0OBBYEFKXI/BlbcKM0/kGLhBKMyn+vYnBVMB8GA1UdIwQY\nMBaAFN5yekjfMcOmUN+fhSPfVzdLXS5lMF0GCCsGAQUFBwEBBFEwTzAlBggrBgEF\nBQcwAYYZaHR0cDovL3N0Zy1yMy5vLmxlbmNyLm9yZzAmBggrBgEFBQcwAoYaaHR0\ncDovL3N0Zy1yMy5pLmxlbmNyLm9yZy8wLwYDVR0RBCgwJoIkc2VjcmV0cy1tYW5h\nZ2VyLnRlc3QuYXBwZG9tYWluLmNsb3VkMEwGA1UdIARFMEMwCAYGZ4EMAQIBMDcG\nCysGAQQBgt8TAQEBMCgwJgYIKwYBBQUHAgEWGmh0dHA6Ly9jcHMubGV0c2VuY3J5\ncHQub3JnMIIBBgYKKwYBBAHWeQIEAgSB9wSB9ADyAHcA3Zk0/KXnJIDJVmh9gTSZ\nCEmySfe1adjHvKs/XMHzbmQAAAF7ushs+wAABAMASDBGAiEA/Poth09OwKLvoysw\n5BR1vW6VuhDERpduTtWXKKooLokCIQDp6qZlu8d1EaNeP+mql9oQRM9jJoyTLNhn\naIkWorr5+gB3ALDMg+Wl+X1rr3wJzChJBIcqx+iLEyxjULfG/SbhbGx3AAABe7rI\nbvQAAAQDAEgwRgIhAOyBcc7if7S/M4kk9puZ4okUaZH3fL/+8SgUzF/ryfGYAiEA\n+1mhCe6ynZAnouAQFt6oDfhwD0JXSowROLnJkGC6QyQwDQYJKoZIhvcNAQELBQAD\nggEBABF5LBBqpWDjvCHeUru/NHrm2BfJvTLbDEYfcT/Woa0NIok5UYS1V84Dns1n\nQKVlTbdMOBL7596CJCaJJNT0q6H4uAzEl+x/LW71puL55b+TN7ZjosOE29K0xFaL\n85YDgXLFnMyf1rZf7Mo+G6kGFJ4yO55AWVXlcCHkMC6UpjaCXZGNA4LPgF4Oom8d\nvnyLd10oLa8XQajNQngJwweaqrbPyOOsq1eEsc3kY06286E4T7akStW+/+KLo/27\nhxl5HDN2Gj5/vf8l80lu13C7fgyUFAYbJnw/02h8AHNv5h0ksFEt2ieLbzVLxvnn\ntmY3WiEwIzkU+M0S6fJwcrfoGec=\n-----END CERTIFICATE-----\n\n-----BEGIN CERTIFICATE-----\nMIIFWzCCA0OgAwIBAgIQTfQrldHumzpMLrM7jRBd1jANBgkqhkiG9w0BAQsFADBm\nMQswCQYDVQQGEwJVUzEzMDEGA1UEChMqKFNUQUdJTkcpIEludGVybmV0IFNlY3Vy\naXR5IFJlc2VhcmNoIEdyb3VwMSIwIAYDVQQDExkoU1RBR0lORykgUHJldGVuZCBQ\nZWFyIFgxMB4XDTIwMDkwNDAwMDAwMFoXDTI1MDkxNTE2MDAwMFowWTELMAkGA1UE\nBhMCVVMxIDAeBgNVBAoTFyhTVEFHSU5HKSBMZXQncyBFbmNyeXB0MSgwJgYDVQQD\nEx8oU1RBR0lORykgQXJ0aWZpY2lhbCBBcHJpY290IFIzMIIBIjANBgkqhkiG9w0B\nAQEFAAOCAQ8AMIIBCgKCAQEAu6TR8+74b46mOE1FUwBrvxzEYLck3iasmKrcQkb+\ngy/z9Jy7QNIAl0B9pVKp4YU76JwxF5DOZZhi7vK7SbCkK6FbHlyU5BiDYIxbbfvO\nL/jVGqdsSjNaJQTg3C3XrJja/HA4WCFEMVoT2wDZm8ABC1N+IQe7Q6FEqc8NwmTS\nnmmRQm4TQvr06DP+zgFK/MNubxWWDSbSKKTH5im5j2fZfg+j/tM1bGaczFWw8/lS\nnukyn5J2L+NJYnclzkXoh9nMFnyPmVbfyDPOc4Y25aTzVoeBKXa/cZ5MM+WddjdL\nbiWvm19f1sYn1aRaAIrkppv7kkn83vcth8XCG39qC2ZvaQIDAQABo4IBEDCCAQww\nDgYDVR0PAQH/BAQDAgGGMB0GA1UdJQQWMBQGCCsGAQUFBwMCBggrBgEFBQcDATAS\nBgNVHRMBAf8ECDAGAQH/AgEAMB0GA1UdDgQWBBTecnpI3zHDplDfn4Uj31c3S10u\nZTAfBgNVHSMEGDAWgBS182Xy/rAKkh/7PH3zRKCsYyXDFDA2BggrBgEFBQcBAQQq\nMCgwJgYIKwYBBQUHMAKGGmh0dHA6Ly9zdGcteDEuaS5sZW5jci5vcmcvMCsGA1Ud\nHwQkMCIwIKAeoByGGmh0dHA6Ly9zdGcteDEuYy5sZW5jci5vcmcvMCIGA1UdIAQb\nMBkwCAYGZ4EMAQIBMA0GCysGAQQBgt8TAQEBMA0GCSqGSIb3DQEBCwUAA4ICAQCN\nDLam9yN0EFxxn/3p+ruWO6n/9goCAM5PT6cC6fkjMs4uas6UGXJjr5j7PoTQf3C1\nvuxiIGRJC6qxV7yc6U0X+w0Mj85sHI5DnQVWN5+D1er7mp13JJA0xbAbHa3Rlczn\ny2Q82XKui8WHuWra0gb2KLpfboYj1Ghgkhr3gau83pC/WQ8HfkwcvSwhIYqTqxoZ\nUq8HIf3M82qS9aKOZE0CEmSyR1zZqQxJUT7emOUapkUN9poJ9zGc+FgRZvdro0XB\nyphWXDaqMYph0DxW/10ig5j4xmmNDjCRmqIKsKoWA52wBTKKXK1na2ty/lW5dhtA\nxkz5rVZFd4sgS4J0O+zm6d5GRkWsNJ4knotGXl8vtS3X40KXeb3A5+/3p0qaD215\nXq8oSNORfB2oI1kQuyEAJ5xvPTdfwRlyRG3lFYodrRg6poUBD/8fNTXMtzydpRgy\nzUQZh/18F6B/iW6cbiRN9r2Hkh05Om+q0/6w0DdZe+8YrNpfhSObr/1eVZbKGMIY\nqKmyZbBNu5ysENIK5MPc14mUeKmFjpN840VR5zunoU52lqpLDua/qIM8idk86xGW\nxx2ml43DO/Ya/tVZVok0mO0TUjzJIfPqyvr455IsIut4RlCR9Iq0EDTve2/ZwCuG\nhSjpTUFGSiQrR2JK2Evp+o6AETUkBCO1aw0PpQBPDQ==\n-----END CERTIFICATE-----\n\n-----BEGIN CERTIFICATE-----\nMIIFVDCCBDygAwIBAgIRAO1dW8lt+99NPs1qSY3Rs8cwDQYJKoZIhvcNAQELBQAw\ncTELMAkGA1UEBhMCVVMxMzAxBgNVBAoTKihTVEFHSU5HKSBJbnRlcm5ldCBTZWN1\ncml0eSBSZXNlYXJjaCBHcm91cDEtMCsGA1UEAxMkKFNUQUdJTkcpIERvY3RvcmVk\nIER1cmlhbiBSb290IENBIFgzMB4XDTIxMDEyMDE5MTQwM1oXDTI0MDkzMDE4MTQw\nM1owZjELMAkGA1UEBhMCVVMxMzAxBgNVBAoTKihTVEFHSU5HKSBJbnRlcm5ldCBT\nZWN1cml0eSBSZXNlYXJjaCBHcm91cDEiMCAGA1UEAxMZKFNUQUdJTkcpIFByZXRl\nbmQgUGVhciBYMTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBALbagEdD\nTa1QgGBWSYkyMhscZXENOBaVRTMX1hceJENgsL0Ma49D3MilI4KS38mtkmdF6cPW\nnL++fgehT0FbRHZgjOEr8UAN4jH6omjrbTD++VZneTsMVaGamQmDdFl5g1gYaigk\nkmx8OiCO68a4QXg4wSyn6iDipKP8utsE+x1E28SA75HOYqpdrk4HGxuULvlr03wZ\nGTIf/oRt2/c+dYmDoaJhge+GOrLAEQByO7+8+vzOwpNAPEx6LW+crEEZ7eBXih6V\nP19sTGy3yfqK5tPtTdXXCOQMKAp+gCj/VByhmIr+0iNDC540gtvV303WpcbwnkkL\nYC0Ft2cYUyHtkstOfRcRO+K2cZozoSwVPyB8/J9RpcRK3jgnX9lujfwA/pAbP0J2\nUPQFxmWFRQnFjaq6rkqbNEBgLy+kFL1NEsRbvFbKrRi5bYy2lNms2NJPZvdNQbT/\n2dBZKmJqxHkxCuOQFjhJQNeO+Njm1Z1iATS/3rts2yZlqXKsxQUzN6vNbD8KnXRM\nEeOXUYvbV4lqfCf8mS14WEbSiMy87GB5S9ucSV1XUrlTG5UGcMSZOBcEUpisRPEm\nQWUOTWIoDQ5FOia/GI+Ki523r2ruEmbmG37EBSBXdxIdndqrjy+QVAmCebyDx9eV\nEGOIpn26bW5LKerumJxa/CFBaKi4bRvmdJRLAgMBAAGjgfEwge4wDgYDVR0PAQH/\nBAQDAgEGMA8GA1UdEwEB/wQFMAMBAf8wHQYDVR0OBBYEFLXzZfL+sAqSH/s8ffNE\noKxjJcMUMB8GA1UdIwQYMBaAFAhX2onHolN5DE/d4JCPdLriJ3NEMDgGCCsGAQUF\nBwEBBCwwKjAoBggrBgEFBQcwAoYcaHR0cDovL3N0Zy1kc3QzLmkubGVuY3Iub3Jn\nLzAtBgNVHR8EJjAkMCKgIKAehhxodHRwOi8vc3RnLWRzdDMuYy5sZW5jci5vcmcv\nMCIGA1UdIAQbMBkwCAYGZ4EMAQIBMA0GCysGAQQBgt8TAQEBMA0GCSqGSIb3DQEB\nCwUAA4IBAQB7tR8B0eIQSS6MhP5kuvGth+dN02DsIhr0yJtk2ehIcPIqSxRRmHGl\n4u2c3QlvEpeRDp2w7eQdRTlI/WnNhY4JOofpMf2zwABgBWtAu0VooQcZZTpQruig\nF/z6xYkBk3UHkjeqxzMN3d1EqGusxJoqgdTouZ5X5QTTIee9nQ3LEhWnRSXDx7Y0\nttR1BGfcdqHopO4IBqAhbkKRjF5zj7OD8cG35omywUbZtOJnftiI0nFcRaxbXo0v\noDfLD0S6+AC2R3tKpqjkNX6/91hrRFglUakyMcZU/xleqbv6+Lr3YD8PsBTub6lI\noZ2lS38fL18Aon458fbc0BPHtenfhKj5\n-----END CERTIFICATE-----\n"
	currentIntermediate = "-----BEGIN CERTIFICATE-----\nMIIFWzCCA0OgAwIBAgIQTfQrldHumzpMLrM7jRBd1jANBgkqhkiG9w0BAQsFADBm\nMQswCQYDVQQGEwJVUzEzMDEGA1UEChMqKFNUQUdJTkcpIEludGVybmV0IFNlY3Vy\naXR5IFJlc2VhcmNoIEdyb3VwMSIwIAYDVQQDExkoU1RBR0lORykgUHJldGVuZCBQ\nZWFyIFgxMB4XDTIwMDkwNDAwMDAwMFoXDTI1MDkxNTE2MDAwMFowWTELMAkGA1UE\nBhMCVVMxIDAeBgNVBAoTFyhTVEFHSU5HKSBMZXQncyBFbmNyeXB0MSgwJgYDVQQD\nEx8oU1RBR0lORykgQXJ0aWZpY2lhbCBBcHJpY290IFIzMIIBIjANBgkqhkiG9w0B\nAQEFAAOCAQ8AMIIBCgKCAQEAu6TR8+74b46mOE1FUwBrvxzEYLck3iasmKrcQkb+\ngy/z9Jy7QNIAl0B9pVKp4YU76JwxF5DOZZhi7vK7SbCkK6FbHlyU5BiDYIxbbfvO\nL/jVGqdsSjNaJQTg3C3XrJja/HA4WCFEMVoT2wDZm8ABC1N+IQe7Q6FEqc8NwmTS\nnmmRQm4TQvr06DP+zgFK/MNubxWWDSbSKKTH5im5j2fZfg+j/tM1bGaczFWw8/lS\nnukyn5J2L+NJYnclzkXoh9nMFnyPmVbfyDPOc4Y25aTzVoeBKXa/cZ5MM+WddjdL\nbiWvm19f1sYn1aRaAIrkppv7kkn83vcth8XCG39qC2ZvaQIDAQABo4IBEDCCAQww\nDgYDVR0PAQH/BAQDAgGGMB0GA1UdJQQWMBQGCCsGAQUFBwMCBggrBgEFBQcDATAS\nBgNVHRMBAf8ECDAGAQH/AgEAMB0GA1UdDgQWBBTecnpI3zHDplDfn4Uj31c3S10u\nZTAfBgNVHSMEGDAWgBS182Xy/rAKkh/7PH3zRKCsYyXDFDA2BggrBgEFBQcBAQQq\nMCgwJgYIKwYBBQUHMAKGGmh0dHA6Ly9zdGcteDEuaS5sZW5jci5vcmcvMCsGA1Ud\nHwQkMCIwIKAeoByGGmh0dHA6Ly9zdGcteDEuYy5sZW5jci5vcmcvMCIGA1UdIAQb\nMBkwCAYGZ4EMAQIBMA0GCysGAQQBgt8TAQEBMA0GCSqGSIb3DQEBCwUAA4ICAQCN\nDLam9yN0EFxxn/3p+ruWO6n/9goCAM5PT6cC6fkjMs4uas6UGXJjr5j7PoTQf3C1\nvuxiIGRJC6qxV7yc6U0X+w0Mj85sHI5DnQVWN5+D1er7mp13JJA0xbAbHa3Rlczn\ny2Q82XKui8WHuWra0gb2KLpfboYj1Ghgkhr3gau83pC/WQ8HfkwcvSwhIYqTqxoZ\nUq8HIf3M82qS9aKOZE0CEmSyR1zZqQxJUT7emOUapkUN9poJ9zGc+FgRZvdro0XB\nyphWXDaqMYph0DxW/10ig5j4xmmNDjCRmqIKsKoWA52wBTKKXK1na2ty/lW5dhtA\nxkz5rVZFd4sgS4J0O+zm6d5GRkWsNJ4knotGXl8vtS3X40KXeb3A5+/3p0qaD215\nXq8oSNORfB2oI1kQuyEAJ5xvPTdfwRlyRG3lFYodrRg6poUBD/8fNTXMtzydpRgy\nzUQZh/18F6B/iW6cbiRN9r2Hkh05Om+q0/6w0DdZe+8YrNpfhSObr/1eVZbKGMIY\nqKmyZbBNu5ysENIK5MPc14mUeKmFjpN840VR5zunoU52lqpLDua/qIM8idk86xGW\nxx2ml43DO/Ya/tVZVok0mO0TUjzJIfPqyvr455IsIut4RlCR9Iq0EDTve2/ZwCuG\nhSjpTUFGSiQrR2JK2Evp+o6AETUkBCO1aw0PpQBPDQ==\n-----END CERTIFICATE-----\n\n-----BEGIN CERTIFICATE-----\nMIIFVDCCBDygAwIBAgIRAO1dW8lt+99NPs1qSY3Rs8cwDQYJKoZIhvcNAQELBQAw\ncTELMAkGA1UEBhMCVVMxMzAxBgNVBAoTKihTVEFHSU5HKSBJbnRlcm5ldCBTZWN1\ncml0eSBSZXNlYXJjaCBHcm91cDEtMCsGA1UEAxMkKFNUQUdJTkcpIERvY3RvcmVk\nIER1cmlhbiBSb290IENBIFgzMB4XDTIxMDEyMDE5MTQwM1oXDTI0MDkzMDE4MTQw\nM1owZjELMAkGA1UEBhMCVVMxMzAxBgNVBAoTKihTVEFHSU5HKSBJbnRlcm5ldCBT\nZWN1cml0eSBSZXNlYXJjaCBHcm91cDEiMCAGA1UEAxMZKFNUQUdJTkcpIFByZXRl\nbmQgUGVhciBYMTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBALbagEdD\nTa1QgGBWSYkyMhscZXENOBaVRTMX1hceJENgsL0Ma49D3MilI4KS38mtkmdF6cPW\nnL++fgehT0FbRHZgjOEr8UAN4jH6omjrbTD++VZneTsMVaGamQmDdFl5g1gYaigk\nkmx8OiCO68a4QXg4wSyn6iDipKP8utsE+x1E28SA75HOYqpdrk4HGxuULvlr03wZ\nGTIf/oRt2/c+dYmDoaJhge+GOrLAEQByO7+8+vzOwpNAPEx6LW+crEEZ7eBXih6V\nP19sTGy3yfqK5tPtTdXXCOQMKAp+gCj/VByhmIr+0iNDC540gtvV303WpcbwnkkL\nYC0Ft2cYUyHtkstOfRcRO+K2cZozoSwVPyB8/J9RpcRK3jgnX9lujfwA/pAbP0J2\nUPQFxmWFRQnFjaq6rkqbNEBgLy+kFL1NEsRbvFbKrRi5bYy2lNms2NJPZvdNQbT/\n2dBZKmJqxHkxCuOQFjhJQNeO+Njm1Z1iATS/3rts2yZlqXKsxQUzN6vNbD8KnXRM\nEeOXUYvbV4lqfCf8mS14WEbSiMy87GB5S9ucSV1XUrlTG5UGcMSZOBcEUpisRPEm\nQWUOTWIoDQ5FOia/GI+Ki523r2ruEmbmG37EBSBXdxIdndqrjy+QVAmCebyDx9eV\nEGOIpn26bW5LKerumJxa/CFBaKi4bRvmdJRLAgMBAAGjgfEwge4wDgYDVR0PAQH/\nBAQDAgEGMA8GA1UdEwEB/wQFMAMBAf8wHQYDVR0OBBYEFLXzZfL+sAqSH/s8ffNE\noKxjJcMUMB8GA1UdIwQYMBaAFAhX2onHolN5DE/d4JCPdLriJ3NEMDgGCCsGAQUF\nBwEBBCwwKjAoBggrBgEFBQcwAoYcaHR0cDovL3N0Zy1kc3QzLmkubGVuY3Iub3Jn\nLzAtBgNVHR8EJjAkMCKgIKAehhxodHRwOi8vc3RnLWRzdDMuYy5sZW5jci5vcmcv\nMCIGA1UdIAQbMBkwCAYGZ4EMAQIBMA0GCysGAQQBgt8TAQEBMA0GCSqGSIb3DQEB\nCwUAA4IBAQB7tR8B0eIQSS6MhP5kuvGth+dN02DsIhr0yJtk2ehIcPIqSxRRmHGl\n4u2c3QlvEpeRDp2w7eQdRTlI/WnNhY4JOofpMf2zwABgBWtAu0VooQcZZTpQruig\nF/z6xYkBk3UHkjeqxzMN3d1EqGusxJoqgdTouZ5X5QTTIee9nQ3LEhWnRSXDx7Y0\nttR1BGfcdqHopO4IBqAhbkKRjF5zj7OD8cG35omywUbZtOJnftiI0nFcRaxbXo0v\noDfLD0S6+AC2R3tKpqjkNX6/91hrRFglUakyMcZU/xleqbv6+Lr3YD8PsBTub6lI\noZ2lS38fL18Aon458fbc0BPHtenfhKj5\n-----END CERTIFICATE-----\n"
	currentPrivKey      = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA0TeG2Ckv8FtyUh5tAlT3EfzpG5iPn1zj+l2LP15eS6LxcIHv\nIMSN+4xSBJ4kes7r0uBybhp+9GGvmLLP0qB1z857lWH6NCD6R82VA7ggM4XHlIDh\n3ieB9eHeLA7ss/x+xqPQHqtbD405DENcHy4M2WZ3xSS1cLX60W0zxPl2MsRQQcuc\nx9FcDcTE0s3H5nzz7xXzj1dqU/JWesV9F8SVde7/YNkJaOVrfVV/XtqOxszA7z8J\n3II/NUvwszds6O/svQu7gwECTl6QcTSlEqKZdm8BZGLe/whCM9tt+VaCRLHnSPij\n2SCN5lvuvRWMvuDGg1MloquuA5KaCuRzpLfK2wIDAQABAoIBADBEr0ePuQ+rCWUI\nv/2ZvKbZwq4rNHd/5tkMW+Py0a6BmVJrp8/XiSpP5VxLX/81XhL41W2xjziykOCZ\n4HinrIaVDM4aHK+KLDQEqiyBfmxkoPcSBQpL8x/XTHq9tr6PsnABuzJYNloQKuk5\nYTeQWEaP7XH+Vh363jMTDq6TH0H2vgL5HHSU1UrCjWDHAH6v+hdfPrx6Wm88449A\n757gLY2JuqPvkN+as7hi2UELntOQDa1cSlnJGCRqpUpVWb1v0SNcZ8/7fApsTRJG\nqDpyqi3N7YhtLCtd8F5Uzo08ML5cPWwruECJK+UfCe3KcpTntmGimDIrWYO1Vxof\nLnS8ZwECgYEA6UpcO54KWndlrr5ldI3UBr2OBM1b1SfgmyFMDKK78SpBrUpK5tMc\n/lwjzsKTZAxTBWDv1etBImfQBr/OQ6ZAsgXyTzwtJFmhSnqGThJo2BkdAkKq08SC\n6HoUSOF2Xndck/h+6qnQIM6m2PAKn5VQjtkRGyaZTcsKBUcJsMehhPMCgYEA5ZU/\ntf5pYPNtk7h/mfRrSKIRLN27QzK3vu+/WbRtehLvjXRicFjny1mzbEciDkw9B7jx\nV1PNrTv2vOWvhqxxwmHOvIYpieCNMnuhKKiKZ7BZY8x5qL9chFHvj8sHdFn7L/R8\nW4RaPSwcUF5xDJj/6Gd2+IZOUVZaEwNo1pKtPHkCgYEAu3o5suNn2JnZClwR9l/A\nA4azqeJKqXr5glF45zKkLMPTsephVSxVQYhUcmVlw2IwGcN0GgqL9pVM1Q+xOCZU\nGXyz5L8sW+j3uH3MjtM2lGtiJ53h4Hss5Jyuzn75/CKaMIPjorvC+Yp5BR+queJp\nsdJ5b8NOMfk4XVNgU0Oq5scCgYA5zR3BQFBfrGoGKwlVRYhNPSB930VqYbaJR+sx\nNo/pkCLnxkmSZ4/UTr0xoacdWmxzKUj554t89f/lBx7uFTR+8AkQxeZnZDWoZB/r\nEKPn/ypCShTHO4abedWKql8yGAV5yWAV2nitthFa2qwzs8GaTZJSd9339HmxF8ap\nXzxmYQKBgCKfWBiZL4x2KEipo5nvu2OBtOxbeXEwp2pXc3ewhOFJr4tI1h19QYGj\n9w4TDwC1da4Z00foRREuRWN9902zkjkBPdb9mMJPKWiRuuStD51BA4YEdCQwe8Hk\n917NTMlTgb4cW7mokWJyqv5uKIDUAOnAdl40zt2VgdofYvgL0X8W\n-----END RSA PRIVATE KEY-----\n"
	//data of this^ specific certificate (after parsing)
	serialNumber   = "fa:48:80:3a:f8:2e:c8:0e:23:a1:1e:5c:38:81:67:f9:c5:73"
	expirationDate = "2021-12-05T10:05:00Z"
	certCommonName = "secrets-manager.test.appdomain.cloud"

	previousCert         = "-----BEGIN CERTIFICATE-----\nMIIFfjCCBGagAwIBAgITAPoY/qqz2E3RF0UL3WaBazTtITANBgkqhkiG9w0BAQsF\nADBZMQswCQYDVQQGEwJVUzEgMB4GA1UEChMXKFNUQUdJTkcpIExldCdzIEVuY3J5\ncHQxKDAmBgNVBAMTHyhTVEFHSU5HKSBBcnRpZmljaWFsIEFwcmljb3QgUjMwHhcN\nMjEwOTA2MDkzMDAyWhcNMjExMjA1MDkzMDAxWjAvMS0wKwYDVQQDEyRzZWNyZXRz\nLW1hbmFnZXIudGVzdC5hcHBkb21haW4uY2xvdWQwggEiMA0GCSqGSIb3DQEBAQUA\nA4IBDwAwggEKAoIBAQCd3dNlJcWvOsF8uwVlcw4zAGw9OBNYxwkO45tk1QMkJEil\nx7csMmVNaRxJNos3580hrqgjDDCAGiuSp79kIF/WSy/kDsZ7ZZwfCo5qhLh2r9Ju\nTxq8L2xYKzcKt2fvRGImhVGOW4qE4GCPrfWF/Zq/JvSCyr9BC1SLXWsxr5WssGx6\nmC53g3YLigLdYxsl+HLqA96FLE7/j8Ybh+ZmwBKqVRIGxzMP9KVg0EHdV1U9Mhwv\nJjjb7gXHJxOge5Xt2xzZ57o87+PBm4gOPOPSlWALi7KIFirsT79IF27+GKU0P3v5\naNwBOfx3fpwNpShCjUbGgM+4CmZRr9kY3anuLU1TAgMBAAGjggJnMIICYzAOBgNV\nHQ8BAf8EBAMCBaAwHQYDVR0lBBYwFAYIKwYBBQUHAwEGCCsGAQUFBwMCMAwGA1Ud\nEwEB/wQCMAAwHQYDVR0OBBYEFByIBVgihgUou/ahPoInE9JiXkjbMB8GA1UdIwQY\nMBaAFN5yekjfMcOmUN+fhSPfVzdLXS5lMF0GCCsGAQUFBwEBBFEwTzAlBggrBgEF\nBQcwAYYZaHR0cDovL3N0Zy1yMy5vLmxlbmNyLm9yZzAmBggrBgEFBQcwAoYaaHR0\ncDovL3N0Zy1yMy5pLmxlbmNyLm9yZy8wLwYDVR0RBCgwJoIkc2VjcmV0cy1tYW5h\nZ2VyLnRlc3QuYXBwZG9tYWluLmNsb3VkMEwGA1UdIARFMEMwCAYGZ4EMAQIBMDcG\nCysGAQQBgt8TAQEBMCgwJgYIKwYBBQUHAgEWGmh0dHA6Ly9jcHMubGV0c2VuY3J5\ncHQub3JnMIIBBAYKKwYBBAHWeQIEAgSB9QSB8gDwAHYAFuhpwdGV6tfD+Jca4/B2\nAfeM4badMahSGLaDfzGoFQgAAAF7uqhhEQAABAMARzBFAiBe392Bs19k/hVqBWeS\nfe/Fc7l7N9OFG/G2IrHOzoOnAQIhAKrJRKiySolV8N62lIUS+OoP2VpJs23MchjH\nzwiCwAnIAHYAKHYaGJAn++880NYaAY12sFBXKcenQRvMvfYE9F1CYVMAAAF7uqhk\n4gAABAMARzBFAiEAxK2Jdb1lTXU8frV2vkwdmaibivXXKvvV7OJpO0ncnNACIH37\n45k8T89OApmKq4MBPfjKGdnEah7Ufrmn7NO9+MGgMA0GCSqGSIb3DQEBCwUAA4IB\nAQAd7JOW/M0Yu/2fkIlYHW9bPydbYzIJNBi/QkIL3I63x4tKmAiFDGKiOxt1usbW\nQ16wpG7z1wvSFHwoUOm46POs0wLDaEEW6AQ38ld7tKOr4EP0h+tcgJqLGRxr/zIU\nhv7Qlok3JEtoEk2BG3ZnolC6NpZRwAuL77Kg/B7S6HiRpO1Q7DuWWKqQYOH0XjlH\nJapQRy8+9vpXTrrPUDuni2ehZtxIISu4qq2xjfYLBMX7FtDQL8r7s2iuChpqg/X+\nzcwHtHTUgFW5srtVsOYQ+fPNKv7jofBNSsoPFKixO1pPX0tjUgTMZfcvzck0EnwO\n4/6WSm7ncBUa+31/J0t1Uz2B\n-----END CERTIFICATE-----\n\n-----BEGIN CERTIFICATE-----\nMIIFWzCCA0OgAwIBAgIQTfQrldHumzpMLrM7jRBd1jANBgkqhkiG9w0BAQsFADBm\nMQswCQYDVQQGEwJVUzEzMDEGA1UEChMqKFNUQUdJTkcpIEludGVybmV0IFNlY3Vy\naXR5IFJlc2VhcmNoIEdyb3VwMSIwIAYDVQQDExkoU1RBR0lORykgUHJldGVuZCBQ\nZWFyIFgxMB4XDTIwMDkwNDAwMDAwMFoXDTI1MDkxNTE2MDAwMFowWTELMAkGA1UE\nBhMCVVMxIDAeBgNVBAoTFyhTVEFHSU5HKSBMZXQncyBFbmNyeXB0MSgwJgYDVQQD\nEx8oU1RBR0lORykgQXJ0aWZpY2lhbCBBcHJpY290IFIzMIIBIjANBgkqhkiG9w0B\nAQEFAAOCAQ8AMIIBCgKCAQEAu6TR8+74b46mOE1FUwBrvxzEYLck3iasmKrcQkb+\ngy/z9Jy7QNIAl0B9pVKp4YU76JwxF5DOZZhi7vK7SbCkK6FbHlyU5BiDYIxbbfvO\nL/jVGqdsSjNaJQTg3C3XrJja/HA4WCFEMVoT2wDZm8ABC1N+IQe7Q6FEqc8NwmTS\nnmmRQm4TQvr06DP+zgFK/MNubxWWDSbSKKTH5im5j2fZfg+j/tM1bGaczFWw8/lS\nnukyn5J2L+NJYnclzkXoh9nMFnyPmVbfyDPOc4Y25aTzVoeBKXa/cZ5MM+WddjdL\nbiWvm19f1sYn1aRaAIrkppv7kkn83vcth8XCG39qC2ZvaQIDAQABo4IBEDCCAQww\nDgYDVR0PAQH/BAQDAgGGMB0GA1UdJQQWMBQGCCsGAQUFBwMCBggrBgEFBQcDATAS\nBgNVHRMBAf8ECDAGAQH/AgEAMB0GA1UdDgQWBBTecnpI3zHDplDfn4Uj31c3S10u\nZTAfBgNVHSMEGDAWgBS182Xy/rAKkh/7PH3zRKCsYyXDFDA2BggrBgEFBQcBAQQq\nMCgwJgYIKwYBBQUHMAKGGmh0dHA6Ly9zdGcteDEuaS5sZW5jci5vcmcvMCsGA1Ud\nHwQkMCIwIKAeoByGGmh0dHA6Ly9zdGcteDEuYy5sZW5jci5vcmcvMCIGA1UdIAQb\nMBkwCAYGZ4EMAQIBMA0GCysGAQQBgt8TAQEBMA0GCSqGSIb3DQEBCwUAA4ICAQCN\nDLam9yN0EFxxn/3p+ruWO6n/9goCAM5PT6cC6fkjMs4uas6UGXJjr5j7PoTQf3C1\nvuxiIGRJC6qxV7yc6U0X+w0Mj85sHI5DnQVWN5+D1er7mp13JJA0xbAbHa3Rlczn\ny2Q82XKui8WHuWra0gb2KLpfboYj1Ghgkhr3gau83pC/WQ8HfkwcvSwhIYqTqxoZ\nUq8HIf3M82qS9aKOZE0CEmSyR1zZqQxJUT7emOUapkUN9poJ9zGc+FgRZvdro0XB\nyphWXDaqMYph0DxW/10ig5j4xmmNDjCRmqIKsKoWA52wBTKKXK1na2ty/lW5dhtA\nxkz5rVZFd4sgS4J0O+zm6d5GRkWsNJ4knotGXl8vtS3X40KXeb3A5+/3p0qaD215\nXq8oSNORfB2oI1kQuyEAJ5xvPTdfwRlyRG3lFYodrRg6poUBD/8fNTXMtzydpRgy\nzUQZh/18F6B/iW6cbiRN9r2Hkh05Om+q0/6w0DdZe+8YrNpfhSObr/1eVZbKGMIY\nqKmyZbBNu5ysENIK5MPc14mUeKmFjpN840VR5zunoU52lqpLDua/qIM8idk86xGW\nxx2ml43DO/Ya/tVZVok0mO0TUjzJIfPqyvr455IsIut4RlCR9Iq0EDTve2/ZwCuG\nhSjpTUFGSiQrR2JK2Evp+o6AETUkBCO1aw0PpQBPDQ==\n-----END CERTIFICATE-----\n\n-----BEGIN CERTIFICATE-----\nMIIFVDCCBDygAwIBAgIRAO1dW8lt+99NPs1qSY3Rs8cwDQYJKoZIhvcNAQELBQAw\ncTELMAkGA1UEBhMCVVMxMzAxBgNVBAoTKihTVEFHSU5HKSBJbnRlcm5ldCBTZWN1\ncml0eSBSZXNlYXJjaCBHcm91cDEtMCsGA1UEAxMkKFNUQUdJTkcpIERvY3RvcmVk\nIER1cmlhbiBSb290IENBIFgzMB4XDTIxMDEyMDE5MTQwM1oXDTI0MDkzMDE4MTQw\nM1owZjELMAkGA1UEBhMCVVMxMzAxBgNVBAoTKihTVEFHSU5HKSBJbnRlcm5ldCBT\nZWN1cml0eSBSZXNlYXJjaCBHcm91cDEiMCAGA1UEAxMZKFNUQUdJTkcpIFByZXRl\nbmQgUGVhciBYMTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBALbagEdD\nTa1QgGBWSYkyMhscZXENOBaVRTMX1hceJENgsL0Ma49D3MilI4KS38mtkmdF6cPW\nnL++fgehT0FbRHZgjOEr8UAN4jH6omjrbTD++VZneTsMVaGamQmDdFl5g1gYaigk\nkmx8OiCO68a4QXg4wSyn6iDipKP8utsE+x1E28SA75HOYqpdrk4HGxuULvlr03wZ\nGTIf/oRt2/c+dYmDoaJhge+GOrLAEQByO7+8+vzOwpNAPEx6LW+crEEZ7eBXih6V\nP19sTGy3yfqK5tPtTdXXCOQMKAp+gCj/VByhmIr+0iNDC540gtvV303WpcbwnkkL\nYC0Ft2cYUyHtkstOfRcRO+K2cZozoSwVPyB8/J9RpcRK3jgnX9lujfwA/pAbP0J2\nUPQFxmWFRQnFjaq6rkqbNEBgLy+kFL1NEsRbvFbKrRi5bYy2lNms2NJPZvdNQbT/\n2dBZKmJqxHkxCuOQFjhJQNeO+Njm1Z1iATS/3rts2yZlqXKsxQUzN6vNbD8KnXRM\nEeOXUYvbV4lqfCf8mS14WEbSiMy87GB5S9ucSV1XUrlTG5UGcMSZOBcEUpisRPEm\nQWUOTWIoDQ5FOia/GI+Ki523r2ruEmbmG37EBSBXdxIdndqrjy+QVAmCebyDx9eV\nEGOIpn26bW5LKerumJxa/CFBaKi4bRvmdJRLAgMBAAGjgfEwge4wDgYDVR0PAQH/\nBAQDAgEGMA8GA1UdEwEB/wQFMAMBAf8wHQYDVR0OBBYEFLXzZfL+sAqSH/s8ffNE\noKxjJcMUMB8GA1UdIwQYMBaAFAhX2onHolN5DE/d4JCPdLriJ3NEMDgGCCsGAQUF\nBwEBBCwwKjAoBggrBgEFBQcwAoYcaHR0cDovL3N0Zy1kc3QzLmkubGVuY3Iub3Jn\nLzAtBgNVHR8EJjAkMCKgIKAehhxodHRwOi8vc3RnLWRzdDMuYy5sZW5jci5vcmcv\nMCIGA1UdIAQbMBkwCAYGZ4EMAQIBMA0GCysGAQQBgt8TAQEBMA0GCSqGSIb3DQEB\nCwUAA4IBAQB7tR8B0eIQSS6MhP5kuvGth+dN02DsIhr0yJtk2ehIcPIqSxRRmHGl\n4u2c3QlvEpeRDp2w7eQdRTlI/WnNhY4JOofpMf2zwABgBWtAu0VooQcZZTpQruig\nF/z6xYkBk3UHkjeqxzMN3d1EqGusxJoqgdTouZ5X5QTTIee9nQ3LEhWnRSXDx7Y0\nttR1BGfcdqHopO4IBqAhbkKRjF5zj7OD8cG35omywUbZtOJnftiI0nFcRaxbXo0v\noDfLD0S6+AC2R3tKpqjkNX6/91hrRFglUakyMcZU/xleqbv6+Lr3YD8PsBTub6lI\noZ2lS38fL18Aon458fbc0BPHtenfhKj5\n-----END CERTIFICATE-----\n"
	previousIntermediate = "-----BEGIN CERTIFICATE-----\nMIIFWzCCA0OgAwIBAgIQTfQrldHumzpMLrM7jRBd1jANBgkqhkiG9w0BAQsFADBm\nMQswCQYDVQQGEwJVUzEzMDEGA1UEChMqKFNUQUdJTkcpIEludGVybmV0IFNlY3Vy\naXR5IFJlc2VhcmNoIEdyb3VwMSIwIAYDVQQDExkoU1RBR0lORykgUHJldGVuZCBQ\nZWFyIFgxMB4XDTIwMDkwNDAwMDAwMFoXDTI1MDkxNTE2MDAwMFowWTELMAkGA1UE\nBhMCVVMxIDAeBgNVBAoTFyhTVEFHSU5HKSBMZXQncyBFbmNyeXB0MSgwJgYDVQQD\nEx8oU1RBR0lORykgQXJ0aWZpY2lhbCBBcHJpY290IFIzMIIBIjANBgkqhkiG9w0B\nAQEFAAOCAQ8AMIIBCgKCAQEAu6TR8+74b46mOE1FUwBrvxzEYLck3iasmKrcQkb+\ngy/z9Jy7QNIAl0B9pVKp4YU76JwxF5DOZZhi7vK7SbCkK6FbHlyU5BiDYIxbbfvO\nL/jVGqdsSjNaJQTg3C3XrJja/HA4WCFEMVoT2wDZm8ABC1N+IQe7Q6FEqc8NwmTS\nnmmRQm4TQvr06DP+zgFK/MNubxWWDSbSKKTH5im5j2fZfg+j/tM1bGaczFWw8/lS\nnukyn5J2L+NJYnclzkXoh9nMFnyPmVbfyDPOc4Y25aTzVoeBKXa/cZ5MM+WddjdL\nbiWvm19f1sYn1aRaAIrkppv7kkn83vcth8XCG39qC2ZvaQIDAQABo4IBEDCCAQww\nDgYDVR0PAQH/BAQDAgGGMB0GA1UdJQQWMBQGCCsGAQUFBwMCBggrBgEFBQcDATAS\nBgNVHRMBAf8ECDAGAQH/AgEAMB0GA1UdDgQWBBTecnpI3zHDplDfn4Uj31c3S10u\nZTAfBgNVHSMEGDAWgBS182Xy/rAKkh/7PH3zRKCsYyXDFDA2BggrBgEFBQcBAQQq\nMCgwJgYIKwYBBQUHMAKGGmh0dHA6Ly9zdGcteDEuaS5sZW5jci5vcmcvMCsGA1Ud\nHwQkMCIwIKAeoByGGmh0dHA6Ly9zdGcteDEuYy5sZW5jci5vcmcvMCIGA1UdIAQb\nMBkwCAYGZ4EMAQIBMA0GCysGAQQBgt8TAQEBMA0GCSqGSIb3DQEBCwUAA4ICAQCN\nDLam9yN0EFxxn/3p+ruWO6n/9goCAM5PT6cC6fkjMs4uas6UGXJjr5j7PoTQf3C1\nvuxiIGRJC6qxV7yc6U0X+w0Mj85sHI5DnQVWN5+D1er7mp13JJA0xbAbHa3Rlczn\ny2Q82XKui8WHuWra0gb2KLpfboYj1Ghgkhr3gau83pC/WQ8HfkwcvSwhIYqTqxoZ\nUq8HIf3M82qS9aKOZE0CEmSyR1zZqQxJUT7emOUapkUN9poJ9zGc+FgRZvdro0XB\nyphWXDaqMYph0DxW/10ig5j4xmmNDjCRmqIKsKoWA52wBTKKXK1na2ty/lW5dhtA\nxkz5rVZFd4sgS4J0O+zm6d5GRkWsNJ4knotGXl8vtS3X40KXeb3A5+/3p0qaD215\nXq8oSNORfB2oI1kQuyEAJ5xvPTdfwRlyRG3lFYodrRg6poUBD/8fNTXMtzydpRgy\nzUQZh/18F6B/iW6cbiRN9r2Hkh05Om+q0/6w0DdZe+8YrNpfhSObr/1eVZbKGMIY\nqKmyZbBNu5ysENIK5MPc14mUeKmFjpN840VR5zunoU52lqpLDua/qIM8idk86xGW\nxx2ml43DO/Ya/tVZVok0mO0TUjzJIfPqyvr455IsIut4RlCR9Iq0EDTve2/ZwCuG\nhSjpTUFGSiQrR2JK2Evp+o6AETUkBCO1aw0PpQBPDQ==\n-----END CERTIFICATE-----\n\n-----BEGIN CERTIFICATE-----\nMIIFVDCCBDygAwIBAgIRAO1dW8lt+99NPs1qSY3Rs8cwDQYJKoZIhvcNAQELBQAw\ncTELMAkGA1UEBhMCVVMxMzAxBgNVBAoTKihTVEFHSU5HKSBJbnRlcm5ldCBTZWN1\ncml0eSBSZXNlYXJjaCBHcm91cDEtMCsGA1UEAxMkKFNUQUdJTkcpIERvY3RvcmVk\nIER1cmlhbiBSb290IENBIFgzMB4XDTIxMDEyMDE5MTQwM1oXDTI0MDkzMDE4MTQw\nM1owZjELMAkGA1UEBhMCVVMxMzAxBgNVBAoTKihTVEFHSU5HKSBJbnRlcm5ldCBT\nZWN1cml0eSBSZXNlYXJjaCBHcm91cDEiMCAGA1UEAxMZKFNUQUdJTkcpIFByZXRl\nbmQgUGVhciBYMTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBALbagEdD\nTa1QgGBWSYkyMhscZXENOBaVRTMX1hceJENgsL0Ma49D3MilI4KS38mtkmdF6cPW\nnL++fgehT0FbRHZgjOEr8UAN4jH6omjrbTD++VZneTsMVaGamQmDdFl5g1gYaigk\nkmx8OiCO68a4QXg4wSyn6iDipKP8utsE+x1E28SA75HOYqpdrk4HGxuULvlr03wZ\nGTIf/oRt2/c+dYmDoaJhge+GOrLAEQByO7+8+vzOwpNAPEx6LW+crEEZ7eBXih6V\nP19sTGy3yfqK5tPtTdXXCOQMKAp+gCj/VByhmIr+0iNDC540gtvV303WpcbwnkkL\nYC0Ft2cYUyHtkstOfRcRO+K2cZozoSwVPyB8/J9RpcRK3jgnX9lujfwA/pAbP0J2\nUPQFxmWFRQnFjaq6rkqbNEBgLy+kFL1NEsRbvFbKrRi5bYy2lNms2NJPZvdNQbT/\n2dBZKmJqxHkxCuOQFjhJQNeO+Njm1Z1iATS/3rts2yZlqXKsxQUzN6vNbD8KnXRM\nEeOXUYvbV4lqfCf8mS14WEbSiMy87GB5S9ucSV1XUrlTG5UGcMSZOBcEUpisRPEm\nQWUOTWIoDQ5FOia/GI+Ki523r2ruEmbmG37EBSBXdxIdndqrjy+QVAmCebyDx9eV\nEGOIpn26bW5LKerumJxa/CFBaKi4bRvmdJRLAgMBAAGjgfEwge4wDgYDVR0PAQH/\nBAQDAgEGMA8GA1UdEwEB/wQFMAMBAf8wHQYDVR0OBBYEFLXzZfL+sAqSH/s8ffNE\noKxjJcMUMB8GA1UdIwQYMBaAFAhX2onHolN5DE/d4JCPdLriJ3NEMDgGCCsGAQUF\nBwEBBCwwKjAoBggrBgEFBQcwAoYcaHR0cDovL3N0Zy1kc3QzLmkubGVuY3Iub3Jn\nLzAtBgNVHR8EJjAkMCKgIKAehhxodHRwOi8vc3RnLWRzdDMuYy5sZW5jci5vcmcv\nMCIGA1UdIAQbMBkwCAYGZ4EMAQIBMA0GCysGAQQBgt8TAQEBMA0GCSqGSIb3DQEB\nCwUAA4IBAQB7tR8B0eIQSS6MhP5kuvGth+dN02DsIhr0yJtk2ehIcPIqSxRRmHGl\n4u2c3QlvEpeRDp2w7eQdRTlI/WnNhY4JOofpMf2zwABgBWtAu0VooQcZZTpQruig\nF/z6xYkBk3UHkjeqxzMN3d1EqGusxJoqgdTouZ5X5QTTIee9nQ3LEhWnRSXDx7Y0\nttR1BGfcdqHopO4IBqAhbkKRjF5zj7OD8cG35omywUbZtOJnftiI0nFcRaxbXo0v\noDfLD0S6+AC2R3tKpqjkNX6/91hrRFglUakyMcZU/xleqbv6+Lr3YD8PsBTub6lI\noZ2lS38fL18Aon458fbc0BPHtenfhKj5\n-----END CERTIFICATE-----\n"
	previousPrivKey      = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEAnd3TZSXFrzrBfLsFZXMOMwBsPTgTWMcJDuObZNUDJCRIpce3\nLDJlTWkcSTaLN+fNIa6oIwwwgBorkqe/ZCBf1ksv5A7Ge2WcHwqOaoS4dq/Sbk8a\nvC9sWCs3Crdn70RiJoVRjluKhOBgj631hf2avyb0gsq/QQtUi11rMa+VrLBsepgu\nd4N2C4oC3WMbJfhy6gPehSxO/4/GG4fmZsASqlUSBsczD/SlYNBB3VdVPTIcLyY4\n2+4FxycToHuV7dsc2ee6PO/jwZuIDjzj0pVgC4uyiBYq7E+/SBdu/hilND97+Wjc\nATn8d36cDaUoQo1GxoDPuApmUa/ZGN2p7i1NUwIDAQABAoIBAG5uAbY7mfFd1IN/\n/+JbfY9HuG+Kjl4HvNphdQ4vw6bAiuEMt6F/D0X7RQIh2Xkd+WyaVJtPp420wM4x\n8bwEuYWZysJpY4ZmKbO9GqqAdNjxXO40/6qsMcnrUPF6IoZI+6+eitJeTqNsoZ9g\nPOOh52HXyirD0M2bM2TZ0GZNQRIurhO42tFw7mSFWuouSxpaxfqH5oTei/Ld4x5b\nrsPHnaYv7QxiZ78qHtMbS9MxVn4sgs4E+M4biK417y7zDqzVJWB3+lnchgqVA84z\nD/YAg7bA/CRP/5Gt0QIyuQ0zuG2/nPzevpn7mman1yCFOMH8PEzyWcRuRWm7ijFw\n698JIEECgYEAwzjlUur3AAwgYVpUPUggOzotjioiDCf4yItUkVrF/vW10ZgBw7H9\ndiUFv+eEHhWshTb1lw8YJc50j2qljtH0rNb8zo03jDpQo4RmoR3gCJl/+e72y21e\n5st3P3dBcW5JGXIPyLA6otqZzTU5tc4TivoQQjAEU9Kaq+1hjqJypokCgYEAzwOy\nu1OooNqDkR6UyjTsssbVWPknsjobPAmVm2j+3xIGaA5ekvw1yG7/QBkWjQqZ+kOT\nynU6tYtjv+74xkQyR8YtRFo+fwZNyHzuxixc7HUI9R+FbgFbSXch5gonP2FQOtV1\n6jw8A6BpE1PT3Rgs0Nr9A0CL27oc8zNrUxISnfsCgYEAqmQRfGLKfUcYSABgQDCg\nuTEZK9lIaFXHBbrecBPLdrIdJLfI6naC5EiCETJQFTYTox4KEvPAvtbI05hgshw8\ns1LdyqZlEkaftWjNbti1fqwDkDDrRTjLuSNjjIhZHVkGAmiUsDRoqVWlIf/PxAf+\n9LE32Z0xWbwa9e611Jmi+gkCgYBPyJMX01RIOi8+vNSHYgJfnHYZRl1gOTjJ2L/K\nF5szCdViQTd92qo3x1+kqoagcReK9oR9INUxprkY/dbvQtVGCEDl+QnhFuLfhBba\nVbqyfyCmqDFahjdShxGPgRZDPRQYuLArSG+wzh/xDPu4WFrdW6jrmfLNCluh941D\nhNGcBQKBgEffQcdK3DLwUF3/tVMlf/Y+1QqzobikaRE3uu5uOyPrrJI313MBj4/l\n2Ud8ppXLs2wCG9x7KC7e8aSzxsipWydl0cOMkU67wSO6MLjEZQnPisQiaazCJfI8\nG+Da0I4euW7oxK2+lU95ZausHII30x9TxJGE62W6jf3LdZOfIGB1\n-----END RSA PRIVATE KEY-----\n"
	previousSerialNumber = "fa:18:fe:aa:b3:d8:4d:d1:17:45:0b:dd:66:81:6b:34:ed:21"

	createdBy    = "CreatedBy"
	errorCode    = "errorCode"
	errorMessage = "errorMessage"
	defaultGroup = "default"
)

var (
	id        = uuid.New()
	secretId  = id.String()
	secretCrn = strings.Replace(smInstanceCrn, "::", ":secret:", 1) + secretId
	certEnd   = strings.Index(currentCert, endCertificate)
	//get only the first cert
	currentSingleCert = currentCert[:certEnd+len(endCertificate)] + "\n"
	versions          = []secretentry.SecretVersion{{
		ID:           uuid.New().String(),
		VersionData:  map[string]interface{}{},
		CreationDate: time.Now().Add(-1 * time.Hour),
		CreatedBy:    createdBy,
		AutoRotated:  false,
		ExtraData:    map[string]interface{}{},
	}}
)

func Test_saveOrderResultToStorage(t *testing.T) {
	oh := initOrdersHandler()
	b, storage = secret_backend.SetupTestBackend(&OrdersBackend{ordersHandler: oh})
	t.Run("First order - order succeeded", func(t *testing.T) {
		setOrdersInProgress(secretId, 2)
		bundleCerts := false
		orderResult := createOrderResult(false, bundleCerts, false)
		oh.saveOrderResultToStorage(orderResult)
		//because of bundleCerts = false
		expectedSecretData := map[string]interface{}{
			secretentry.FieldCertificate:  currentSingleCert,
			secretentry.FieldIntermediate: currentIntermediate,
			secretentry.FieldPrivateKey:   currentPrivKey,
		}
		//get secret
		req := &logical.Request{
			Operation: logical.ReadOperation,
			Path:      PathSecrets + secretId,
			Storage:   storage,
			Data:      make(map[string]interface{}),
			Connection: &logical.Connection{
				RemoteAddr: "0.0.0.0",
			},
		}
		resp, err := b.HandleRequest(context.Background(), req)
		assert.NilError(t, err)
		//common fields
		assert.Equal(t, false, resp.IsError())
		assert.Equal(t, resp.Data[secretentry.FieldSecretType], secretentry.SecretTypePublicCert)
		assert.Equal(t, resp.Data[secretentry.FieldName], certName1)
		assert.Equal(t, resp.Data[secretentry.FieldDescription], certDesc)
		assert.Equal(t, true, reflect.DeepEqual(resp.Data[secretentry.FieldLabels].([]string), labels))
		assert.Equal(t, resp.Data[secretentry.FieldStateDescription], secretentry.GetNistStateDescription(secretentry.StateActive))
		assert.Equal(t, resp.Data[secretentry.FieldCreatedBy], createdBy)
		//specific fields
		assert.Equal(t, resp.Data[secretentry.FieldKeyAlgorithm], keyType)
		assert.Equal(t, resp.Data[secretentry.FieldCommonName], certCommonName)
		assert.Equal(t, true, reflect.DeepEqual(resp.Data[secretentry.FieldAltNames].([]string), []string{certCommonName}))
		assert.DeepEqual(t, resp.Data[secretentry.FieldSecretData], expectedSecretData)
		//issuance info
		assert.Equal(t, resp.Data[FieldIssuanceInfo].(map[string]interface{})[FieldAutoRotated], false)
		assert.Equal(t, resp.Data[FieldIssuanceInfo].(map[string]interface{})[FieldBundleCert], false)
		assert.Equal(t, resp.Data[FieldIssuanceInfo].(map[string]interface{})[FieldCAConfig], caConfig)
		assert.Equal(t, resp.Data[FieldIssuanceInfo].(map[string]interface{})[FieldDNSConfig], dnsConfig)
		assert.Equal(t, resp.Data[FieldIssuanceInfo].(map[string]interface{})[secretentry.FieldStateDescription], secretentry.GetNistStateDescription(secretentry.StateActive))
		//it's the first version of this secret
		assert.Equal(t, resp.Data[secretentry.FieldVersionsTotal], 1)
		assert.Equal(t, resp.Data[secretentry.FieldVersions].([]map[string]interface{})[0][secretentry.FieldCreatedBy], createdBy)
		assert.Equal(t, resp.Data[secretentry.FieldVersions].([]map[string]interface{})[0][secretentry.FieldSerialNumber], serialNumber)
		assert.Equal(t, resp.Data[secretentry.FieldVersions].([]map[string]interface{})[0][secretentry.FieldExpirationDate], expirationDate)
		assert.Equal(t, resp.Data[secretentry.FieldVersions].([]map[string]interface{})[0][secretentry.FieldPayloadAvailable], true)

		checkOrdersInProgress(t, []OrderDetails{{GroupId: defaultGroup, Id: "1", Attempts: 1}}) //only the second of 2
	})

	t.Run("First order - order failed", func(t *testing.T) {
		setOrdersInProgress(secretId, 1)
		orderResult := createOrderResult(true, false, false)
		expectedSecretData := map[string]string{}
		oh.saveOrderResultToStorage(orderResult)
		//get secret
		req := &logical.Request{
			Operation: logical.ReadOperation,
			Path:      PathSecrets + secretId,
			Storage:   storage,
			Data:      make(map[string]interface{}),
			Connection: &logical.Connection{
				RemoteAddr: "0.0.0.0",
			},
		}
		resp, err := b.HandleRequest(context.Background(), req)
		assert.NilError(t, err)
		assert.Equal(t, false, resp.IsError())
		//common fields
		assert.Equal(t, resp.Data[secretentry.FieldSecretType], secretentry.SecretTypePublicCert)
		assert.Equal(t, resp.Data[secretentry.FieldName], certName1)
		assert.Equal(t, resp.Data[secretentry.FieldDescription], certDesc)
		assert.Equal(t, true, reflect.DeepEqual(resp.Data[secretentry.FieldLabels].([]string), labels))
		assert.Equal(t, resp.Data[secretentry.FieldStateDescription], secretentry.GetNistStateDescription(secretentry.StateDeactivated))
		assert.Equal(t, resp.Data[secretentry.FieldCreatedBy], createdBy)
		//specific fields
		assert.Equal(t, resp.Data[secretentry.FieldKeyAlgorithm], keyType)
		assert.Equal(t, resp.Data[secretentry.FieldCommonName], certCommonName)
		assert.DeepEqual(t, resp.Data[secretentry.FieldSecretData], expectedSecretData)
		//issuance info
		assert.Equal(t, resp.Data[FieldIssuanceInfo].(map[string]interface{})[FieldAutoRotated], false)
		assert.Equal(t, resp.Data[FieldIssuanceInfo].(map[string]interface{})[FieldBundleCert], false)
		assert.Equal(t, resp.Data[FieldIssuanceInfo].(map[string]interface{})[FieldCAConfig], caConfig)
		assert.Equal(t, resp.Data[FieldIssuanceInfo].(map[string]interface{})[FieldDNSConfig], dnsConfig)
		assert.Equal(t, resp.Data[FieldIssuanceInfo].(map[string]interface{})[FieldErrorCode], errorCode)
		assert.Equal(t, resp.Data[FieldIssuanceInfo].(map[string]interface{})[FieldErrorMessage], errorMessage)
		assert.Equal(t, resp.Data[FieldIssuanceInfo].(map[string]interface{})[secretentry.FieldStateDescription], secretentry.GetNistStateDescription(secretentry.StateDeactivated))
		//versions
		assert.Equal(t, resp.Data[secretentry.FieldVersionsTotal], 1)
		checkOrdersInProgress(t, []OrderDetails{})
	})

	t.Run("Rotation - order succeeded", func(t *testing.T) {
		setOrdersInProgress(secretId, 3)
		bundleCerts := true
		orderResult := createOrderResult(false, bundleCerts, true)
		oh.saveOrderResultToStorage(orderResult)
		//because of bundleCerts = true
		expectedSecretData := map[string]interface{}{
			secretentry.FieldCertificate:  currentCert,
			secretentry.FieldIntermediate: currentIntermediate,
			secretentry.FieldPrivateKey:   currentPrivKey,
		}
		//get secret
		req := &logical.Request{
			Operation: logical.ReadOperation,
			Path:      PathSecrets + secretId,
			Storage:   storage,
			Data:      make(map[string]interface{}),
			Connection: &logical.Connection{
				RemoteAddr: "0.0.0.0",
			},
		}
		resp, err := b.HandleRequest(context.Background(), req)
		assert.NilError(t, err)
		assert.Equal(t, false, resp.IsError())
		//common fields
		assert.Equal(t, resp.Data[secretentry.FieldSecretType], secretentry.SecretTypePublicCert)
		assert.Equal(t, resp.Data[secretentry.FieldName], certName1)
		assert.Equal(t, resp.Data[secretentry.FieldDescription], certDesc)
		assert.Equal(t, true, reflect.DeepEqual(resp.Data[secretentry.FieldLabels].([]string), labels))
		assert.Equal(t, resp.Data[secretentry.FieldStateDescription], secretentry.GetNistStateDescription(secretentry.StateActive))
		assert.Equal(t, resp.Data[secretentry.FieldCreatedBy], createdBy)
		//specific fields
		assert.Equal(t, resp.Data[secretentry.FieldKeyAlgorithm], keyType)
		assert.Equal(t, resp.Data[secretentry.FieldCommonName], certCommonName)
		assert.Equal(t, true, reflect.DeepEqual(resp.Data[secretentry.FieldAltNames].([]string), []string{certCommonName}))
		assert.DeepEqual(t, resp.Data[secretentry.FieldSecretData], expectedSecretData)
		//issuance info
		assert.Equal(t, resp.Data[FieldIssuanceInfo].(map[string]interface{})[FieldAutoRotated], false)
		assert.Equal(t, resp.Data[FieldIssuanceInfo].(map[string]interface{})[FieldBundleCert], bundleCerts)
		assert.Equal(t, resp.Data[FieldIssuanceInfo].(map[string]interface{})[FieldCAConfig], caConfig)
		assert.Equal(t, resp.Data[FieldIssuanceInfo].(map[string]interface{})[FieldDNSConfig], dnsConfig)
		assert.Equal(t, resp.Data[FieldIssuanceInfo].(map[string]interface{})[secretentry.FieldStateDescription], secretentry.GetNistStateDescription(secretentry.StateActive))
		//versions
		assert.Equal(t, resp.Data[secretentry.FieldVersionsTotal], 2)
		//the second version is the current order
		assert.Equal(t, resp.Data[secretentry.FieldVersions].([]map[string]interface{})[1][secretentry.FieldCreatedBy], createdBy)
		assert.Equal(t, resp.Data[secretentry.FieldVersions].([]map[string]interface{})[1][secretentry.FieldSerialNumber], serialNumber)
		assert.Equal(t, resp.Data[secretentry.FieldVersions].([]map[string]interface{})[1][secretentry.FieldExpirationDate], expirationDate)
		assert.Equal(t, resp.Data[secretentry.FieldVersions].([]map[string]interface{})[1][secretentry.FieldPayloadAvailable], true)
		checkOrdersInProgress(t, []OrderDetails{{GroupId: defaultGroup, Id: "0", Attempts: 1}, {GroupId: defaultGroup, Id: "2", Attempts: 1}}) //the first and the last should remain, the one before last (current order) should be removed
	})

	t.Run("Rotation - order failed", func(t *testing.T) {
		setOrdersInProgress(secretId, 0)
		bundleCerts := true
		orderResult := createOrderResult(true, bundleCerts, true)
		//because of bundleCerts = false
		//expected secret data is from the previous version
		expectedSecretData := map[string]interface{}{
			secretentry.FieldCertificate:  previousCert,
			secretentry.FieldIntermediate: previousIntermediate,
			secretentry.FieldPrivateKey:   previousPrivKey,
		}
		oh.saveOrderResultToStorage(orderResult)
		//get secret
		req := &logical.Request{
			Operation: logical.ReadOperation,
			Path:      PathSecrets + secretId,
			Storage:   storage,
			Data:      make(map[string]interface{}),
			Connection: &logical.Connection{
				RemoteAddr: "0.0.0.0",
			},
		}
		resp, err := b.HandleRequest(context.Background(), req)
		assert.NilError(t, err)
		assert.Equal(t, false, resp.IsError())
		//common fields
		assert.Equal(t, resp.Data[secretentry.FieldSecretType], secretentry.SecretTypePublicCert)
		assert.Equal(t, resp.Data[secretentry.FieldName], certName1)
		assert.Equal(t, resp.Data[secretentry.FieldDescription], certDesc)
		assert.Equal(t, true, reflect.DeepEqual(resp.Data[secretentry.FieldLabels].([]string), labels))
		assert.Equal(t, resp.Data[secretentry.FieldStateDescription], secretentry.GetNistStateDescription(secretentry.StateActive))
		assert.Equal(t, resp.Data[secretentry.FieldCreatedBy], createdBy)
		//specific fields
		assert.Equal(t, resp.Data[secretentry.FieldKeyAlgorithm], keyType)
		assert.Equal(t, resp.Data[secretentry.FieldCommonName], certCommonName)
		assert.DeepEqual(t, resp.Data[secretentry.FieldSecretData], expectedSecretData)
		//issuance info
		assert.Equal(t, resp.Data[FieldIssuanceInfo].(map[string]interface{})[FieldAutoRotated], false)
		assert.Equal(t, resp.Data[FieldIssuanceInfo].(map[string]interface{})[FieldBundleCert], bundleCerts)
		assert.Equal(t, resp.Data[FieldIssuanceInfo].(map[string]interface{})[FieldCAConfig], caConfig)
		assert.Equal(t, resp.Data[FieldIssuanceInfo].(map[string]interface{})[FieldDNSConfig], dnsConfig)
		assert.Equal(t, resp.Data[FieldIssuanceInfo].(map[string]interface{})[FieldErrorCode], errorCode)
		assert.Equal(t, resp.Data[FieldIssuanceInfo].(map[string]interface{})[FieldErrorMessage], errorMessage)
		assert.Equal(t, resp.Data[FieldIssuanceInfo].(map[string]interface{})[secretentry.FieldStateDescription], secretentry.GetNistStateDescription(secretentry.StateDeactivated))
		//versions
		assert.Equal(t, resp.Data[secretentry.FieldVersionsTotal], 1)
		checkOrdersInProgress(t, []OrderDetails{})
	})

	t.Run("First order - order succeeded, but parsing failed", func(t *testing.T) {
		badParserHandler := &OrdersHandler{
			runningOrders: make(map[string]WorkItem),
			beforeOrders:  make(map[string]WorkItem),
			parser:        &parserMock{},
		}
		setOrdersInProgress(secretId, 2)
		bundleCerts := false
		orderResult := createOrderResult(false, bundleCerts, false)
		badParserHandler.saveOrderResultToStorage(orderResult)
		//get secret
		req := &logical.Request{
			Operation: logical.ReadOperation,
			Path:      PathSecrets + secretId,
			Storage:   storage,
			Data:      make(map[string]interface{}),
			Connection: &logical.Connection{
				RemoteAddr: "0.0.0.0",
			},
		}
		resp, err := b.HandleRequest(context.Background(), req)
		assert.NilError(t, err)
		//common fields
		assert.Equal(t, false, resp.IsError())
		assert.Equal(t, resp.Data[secretentry.FieldSecretType], secretentry.SecretTypePublicCert)
		assert.Equal(t, resp.Data[secretentry.FieldName], certName1)
		assert.Equal(t, resp.Data[secretentry.FieldDescription], certDesc)
		assert.Equal(t, true, reflect.DeepEqual(resp.Data[secretentry.FieldLabels].([]string), labels))
		assert.Equal(t, resp.Data[secretentry.FieldStateDescription], secretentry.GetNistStateDescription(secretentry.StateDeactivated))
		assert.Equal(t, resp.Data[secretentry.FieldCreatedBy], createdBy)
		//issuance info
		assert.Equal(t, resp.Data[FieldIssuanceInfo].(map[string]interface{})[FieldAutoRotated], false)
		assert.Equal(t, resp.Data[FieldIssuanceInfo].(map[string]interface{})[FieldBundleCert], false)
		assert.Equal(t, resp.Data[FieldIssuanceInfo].(map[string]interface{})[FieldCAConfig], caConfig)
		assert.Equal(t, resp.Data[FieldIssuanceInfo].(map[string]interface{})[FieldDNSConfig], dnsConfig)
		assert.Equal(t, resp.Data[FieldIssuanceInfo].(map[string]interface{})[FieldErrorCode], logdna.Error07063)
		assert.Equal(t, resp.Data[FieldIssuanceInfo].(map[string]interface{})[FieldErrorMessage], failedToParseCertificate)
		assert.Equal(t, resp.Data[FieldIssuanceInfo].(map[string]interface{})[secretentry.FieldStateDescription], secretentry.GetNistStateDescription(secretentry.StateDeactivated))
		checkOrdersInProgress(t, []OrderDetails{{GroupId: defaultGroup, Id: "1", Attempts: 1}}) //only the second of 2
	})

}

func createOrderResult(withError bool, bundleCert bool, rotation bool) Result {
	certMetadata := certificate_struct.CertificateMetadata{
		KeyAlgorithm: keyType,
		CommonName:   certCommonName,
		IssuanceInfo: map[string]interface{}{secretentry.FieldState: secretentry.StatePreActivation,
			FieldBundleCert: bundleCert, FieldCAConfig: caConfig, FieldDNSConfig: dnsConfig, FieldAutoRotated: false}}
	entryState := secretentry.StatePreActivation
	versionData := map[string]interface{}{}
	if rotation {
		entryState = secretentry.StateActive
		versionData = secretData
	}
	versions[0].VersionData = versionData

	orderResult := Result{
		workItem: WorkItem{
			requestID:  uuid.UUID{},
			caConfig:   &CAUserConfig{},
			dnsConfig:  &ProviderConfig{},
			keyType:    keyType,
			privateKey: nil,
			csr:        nil,
			domains:    []string{certCommonName},
			isBundle:   bundleCert,
			secretEntry: &secretentry.SecretEntry{
				ID:             secretId,
				Name:           certName1,
				Description:    certDesc,
				Labels:         labels,
				ExtraData:      certMetadata,
				Versions:       versions,
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
				Type:             secretentry.SecretTypePublicCert,
				CRN:              secretCrn,
				GroupID:          "",
				State:            entryState,
				VersionsTotal:    len(versions),
				PayloadUpdatedAt: versions[len(versions)-1].CreationDate,
			},
			storage: storage,
		},
		Error: nil,
		certificate: &legoCert.Resource{
			PrivateKey:        []byte(currentPrivKey),
			Certificate:       []byte(currentCert),
			IssuerCertificate: []byte(currentIntermediate),
		},
	}
	if withError {
		err := buildOrderError(errorCode, errorMessage)
		orderResult.Error = errors.New("some additional text from ACME client " + err.Error() + "another text")
		orderResult.certificate = nil
	}
	return orderResult
}

func resetOrdersInProgress() {
	oh.runningOrders = make(map[string]WorkItem)
	ordersInProgress := getOrdersInProgress(storage)
	ordersInProgress.Orders = []OrderDetails{}
	ordersInProgress.save(storage)
}

func setOrdersInProgress(id string, count int) {
	ordersInProgress := getOrdersInProgress(storage)
	switch count {
	case 0:
		ordersInProgress.Orders = []OrderDetails{}
	case 1:
		ordersInProgress.Orders = []OrderDetails{{GroupId: defaultGroup, Id: id, Attempts: 1}}
	default:
		ids := make([]OrderDetails, count)
		//build array of ids of length count
		for i := range ids {
			ids[i] = OrderDetails{GroupId: defaultGroup, Id: strconv.Itoa(i), Attempts: 1}
		}
		//the one before last will be expected id
		ids[count-2] = OrderDetails{GroupId: defaultGroup, Id: id, Attempts: 1}
		ordersInProgress.Orders = ids
	}
	ordersInProgress.save(storage)
}

func checkOrdersInProgress(t *testing.T, secretIds []OrderDetails) {
	ordersInProgress := getOrdersInProgress(storage)
	assert.DeepEqual(t, ordersInProgress, &OrdersInProgress{Orders: secretIds})
}
