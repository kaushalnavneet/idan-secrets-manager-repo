package publiccerts

import (
	"context"
	"errors"
	legoCert "github.com/go-acme/lego/v4/certificate"
	"github.com/google/uuid"
	"github.com/hashicorp/vault/sdk/logical"
	"github.ibm.com/security-services/secrets-manager-common-utils/secret_metadata_entry"
	"github.ibm.com/security-services/secrets-manager-common-utils/secret_metadata_entry/certificate"
	"github.ibm.com/security-services/secrets-manager-common-utils/secret_metadata_entry/policies"
	"github.ibm.com/security-services/secrets-manager-vault-plugins-common/logdna"
	"github.ibm.com/security-services/secrets-manager-vault-plugins-common/secret_backend"
	"github.ibm.com/security-services/secrets-manager-vault-plugins-common/secretentry"
	"gotest.tools/v3/assert"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"
)

const (
	currentCert         = "-----BEGIN CERTIFICATE-----\nMIIDTjCCAjYCCQDL1LbqyGobWjANBgkqhkiG9w0BAQsFADBpMQswCQYDVQQGEwJ1\nczERMA8GA1UECAwIdXMtc291dGgxDzANBgNVBAcMBkRhbC0xMDEMMAoGA1UECgwD\nSUJNMRMwEQYDVQQLDApDbG91ZENlcnRzMRMwEQYDVQQDDApkb21haW4uY29tMB4X\nDTIyMDQwMzA4MTc0M1oXDTMwMDYyMDA4MTc0M1owaTELMAkGA1UEBhMCdXMxETAP\nBgNVBAgMCHVzLXNvdXRoMQ8wDQYDVQQHDAZEYWwtMTAxDDAKBgNVBAoMA0lCTTET\nMBEGA1UECwwKQ2xvdWRDZXJ0czETMBEGA1UEAwwKZG9tYWluLmNvbTCCASIwDQYJ\nKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMXuLQRXHvmA58gCMu31GquwKCuLbLpc\nJJ0MgZeDWVxmevTg6rPnMGG7ELz9v5xseUi3rcYp5joDdAYk6fxGB17OKYU0VbRj\nbb0KLsmN0Y4LTu8W9HmYgoIjwJ7GOINZB/vFwhQdgLyTUThfYU3cGTlOA3qP+J26\nsTWjwwGQVtXyHdY6E6yRf/dbodnhNMY8+6mpXOBQtDuafYT2woNCjpsVtSN+im6K\nSymG5sHzEvigQTa2nRhS/a9kyYpt4rOFJpk56AnRwcofg4EJ9APRLZddFfF+XL3s\n6rcBqHg9i5eCEgwdmvbz1pAB7BLfjOgPTu+2Y5HcT7Yv7l+Ae9k4DUECAwEAATAN\nBgkqhkiG9w0BAQsFAAOCAQEALjdl97vLmV2ZWiThCVNcNqUy+7E9Z1QUkMUnynM8\nOFOTGzBwWz38vILzmCL1LMa/X6L9XxwBpRv130idCORJPaUvQORdlG6WXvSTL6Bn\nakAuHaZn/PJ7hRQdD8SiWLGXtwOhjy/FOGb3Xkk+Wbq/ngfwREphWG9+b0VCF3g0\nA7CMjR9MBUFqLxEGwwI7qpfgWyZ3XXOFMmBdt88dtU8v9NnQtjiRi6FdGKXa7rOq\n85kc64Hbsg/x1x1vX5lt2auexvzjwqm7sUR55cFNckNP8UA4eOvY+mYsEitc5fcY\naBx0so1N3IP1AbCARf7+gltsz2CjRH9OFXmOFF0Cb4nYcQ==\n-----END CERTIFICATE-----\n\n-----BEGIN CERTIFICATE-----\nMIIDTjCCAjYCCQDL1LbqyGobWjANBgkqhkiG9w0BAQsFADBpMQswCQYDVQQGEwJ1\nczERMA8GA1UECAwIdXMtc291dGgxDzANBgNVBAcMBkRhbC0xMDEMMAoGA1UECgwD\nSUJNMRMwEQYDVQQLDApDbG91ZENlcnRzMRMwEQYDVQQDDApkb21haW4uY29tMB4X\nDTIyMDQwMzA4MTc0M1oXDTMwMDYyMDA4MTc0M1owaTELMAkGA1UEBhMCdXMxETAP\nBgNVBAgMCHVzLXNvdXRoMQ8wDQYDVQQHDAZEYWwtMTAxDDAKBgNVBAoMA0lCTTET\nMBEGA1UECwwKQ2xvdWRDZXJ0czETMBEGA1UEAwwKZG9tYWluLmNvbTCCASIwDQYJ\nKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMXuLQRXHvmA58gCMu31GquwKCuLbLpc\nJJ0MgZeDWVxmevTg6rPnMGG7ELz9v5xseUi3rcYp5joDdAYk6fxGB17OKYU0VbRj\nbb0KLsmN0Y4LTu8W9HmYgoIjwJ7GOINZB/vFwhQdgLyTUThfYU3cGTlOA3qP+J26\nsTWjwwGQVtXyHdY6E6yRf/dbodnhNMY8+6mpXOBQtDuafYT2woNCjpsVtSN+im6K\nSymG5sHzEvigQTa2nRhS/a9kyYpt4rOFJpk56AnRwcofg4EJ9APRLZddFfF+XL3s\n6rcBqHg9i5eCEgwdmvbz1pAB7BLfjOgPTu+2Y5HcT7Yv7l+Ae9k4DUECAwEAATAN\nBgkqhkiG9w0BAQsFAAOCAQEALjdl97vLmV2ZWiThCVNcNqUy+7E9Z1QUkMUnynM8\nOFOTGzBwWz38vILzmCL1LMa/X6L9XxwBpRv130idCORJPaUvQORdlG6WXvSTL6Bn\nakAuHaZn/PJ7hRQdD8SiWLGXtwOhjy/FOGb3Xkk+Wbq/ngfwREphWG9+b0VCF3g0\nA7CMjR9MBUFqLxEGwwI7qpfgWyZ3XXOFMmBdt88dtU8v9NnQtjiRi6FdGKXa7rOq\n85kc64Hbsg/x1x1vX5lt2auexvzjwqm7sUR55cFNckNP8UA4eOvY+mYsEitc5fcY\naBx0so1N3IP1AbCARf7+gltsz2CjRH9OFXmOFF0Cb4nYcQ==\n-----END CERTIFICATE-----\n"
	currentIntermediate = "-----BEGIN CERTIFICATE-----\nMIIDTjCCAjYCCQDL1LbqyGobWjANBgkqhkiG9w0BAQsFADBpMQswCQYDVQQGEwJ1\nczERMA8GA1UECAwIdXMtc291dGgxDzANBgNVBAcMBkRhbC0xMDEMMAoGA1UECgwD\nSUJNMRMwEQYDVQQLDApDbG91ZENlcnRzMRMwEQYDVQQDDApkb21haW4uY29tMB4X\nDTIyMDQwMzA4MTc0M1oXDTMwMDYyMDA4MTc0M1owaTELMAkGA1UEBhMCdXMxETAP\nBgNVBAgMCHVzLXNvdXRoMQ8wDQYDVQQHDAZEYWwtMTAxDDAKBgNVBAoMA0lCTTET\nMBEGA1UECwwKQ2xvdWRDZXJ0czETMBEGA1UEAwwKZG9tYWluLmNvbTCCASIwDQYJ\nKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMXuLQRXHvmA58gCMu31GquwKCuLbLpc\nJJ0MgZeDWVxmevTg6rPnMGG7ELz9v5xseUi3rcYp5joDdAYk6fxGB17OKYU0VbRj\nbb0KLsmN0Y4LTu8W9HmYgoIjwJ7GOINZB/vFwhQdgLyTUThfYU3cGTlOA3qP+J26\nsTWjwwGQVtXyHdY6E6yRf/dbodnhNMY8+6mpXOBQtDuafYT2woNCjpsVtSN+im6K\nSymG5sHzEvigQTa2nRhS/a9kyYpt4rOFJpk56AnRwcofg4EJ9APRLZddFfF+XL3s\n6rcBqHg9i5eCEgwdmvbz1pAB7BLfjOgPTu+2Y5HcT7Yv7l+Ae9k4DUECAwEAATAN\nBgkqhkiG9w0BAQsFAAOCAQEALjdl97vLmV2ZWiThCVNcNqUy+7E9Z1QUkMUnynM8\nOFOTGzBwWz38vILzmCL1LMa/X6L9XxwBpRv130idCORJPaUvQORdlG6WXvSTL6Bn\nakAuHaZn/PJ7hRQdD8SiWLGXtwOhjy/FOGb3Xkk+Wbq/ngfwREphWG9+b0VCF3g0\nA7CMjR9MBUFqLxEGwwI7qpfgWyZ3XXOFMmBdt88dtU8v9NnQtjiRi6FdGKXa7rOq\n85kc64Hbsg/x1x1vX5lt2auexvzjwqm7sUR55cFNckNP8UA4eOvY+mYsEitc5fcY\naBx0so1N3IP1AbCARf7+gltsz2CjRH9OFXmOFF0Cb4nYcQ==\n-----END CERTIFICATE-----\n"
	currentPrivKey      = "-----BEGIN PRIVATE KEY-----\nMIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDF7i0EVx75gOfI\nAjLt9RqrsCgri2y6XCSdDIGXg1lcZnr04Oqz5zBhuxC8/b+cbHlIt63GKeY6A3QG\nJOn8RgdezimFNFW0Y229Ci7JjdGOC07vFvR5mIKCI8CexjiDWQf7xcIUHYC8k1E4\nX2FN3Bk5TgN6j/idurE1o8MBkFbV8h3WOhOskX/3W6HZ4TTGPPupqVzgULQ7mn2E\n9sKDQo6bFbUjfopuiksphubB8xL4oEE2tp0YUv2vZMmKbeKzhSaZOegJ0cHKH4OB\nCfQD0S2XXRXxfly97Oq3Aah4PYuXghIMHZr289aQAewS34zoD07vtmOR3E+2L+5f\ngHvZOA1BAgMBAAECggEAPmxQfEbxuOTDtNukrlGX+L/U227ceqXm0jUIhf1h6HdV\nnfd1bgmiw5/YtpIcpTu8wIdVYeMC/hbqt6latjprxqWkiKMpyHt3N6CHgv+cMH02\nhscpkVPdDSgzbp+7YQlqMCh9fhST7mVTv0Ctkn2w4tbM2BGh6jTgALfGH68jA9QK\nKITLX8gDRe6UJAV9MIU3tLjnugBmBKX+DRTNHtptdm6ZMBBymkuYqIt34/sosUqF\njXxtKstpT3KGzshT/73y9FbjOuo39Fzo7IIPegJnYWWISaY8DaO/7VT/k+5r3/zM\ntBBgAL42lR9sI3EfzpUnnOAvxD5a45rcnZIXsQYTdQKBgQD+8JIQQaFgKrN7paKH\nst4PjXNgS87TknCqvJhfmW4vKODAI/2gWjJhiEhMb9w5PBpR+ohNc/E2CaYm2tGE\nJGyJxy1DP3CnNnufZRcbwWsjCyigYgGppf2J+IPZhcldsYfaY9t6R1akOSTFDJvZ\nMp4/NrRzrLq6iiHm2+osFJFE/wKBgQDGwOiU0ZX6/WV54wYlJ6dNMKbwS24fRRlk\nKkRfuN/gD5qDF0njiwIhPWoL5FbG9EGUbEyykF8zzRVrPmdi1MdakNpgIG35Y2Mf\naB7wI1yMhpIMqeySJisucdyvF4lfpYnlNRUt3OfnNBjff62fE+uUDRWMTwcDhEsp\nlOsZ0IttvwKBgQDcl0abgF5lOq2Q6LIonrGcXXWethmhYg3Q/l0OI1F+xu0p9Dpp\n/IGpeOWuFgBFGedgVdqIwjDN5C17Y010/JtZ4BkfHg6Y8QCo3CzRnFvat7YQiJ0N\nsQ4fywQzPJsPUiTN6Cept36VnMhfJFjZ5/2bjvc3PBdaf1l0S4dlWuqT+wKBgD6m\nPCn8zpvpF/2NtDguAaxxM433GOU+cLyEHj1WFyuXf4rm4mGZRbiYlT7eYQQhpjJU\n2PBIVdoMQT4m04vxqk0/77XxQvkjfPE/btEfNGMPYCYhwfJnmaDwPzHp52GA2rCn\nRN/KDEdywoxgwKeuLcnjPfGWT42qO88Fo/3lIK4dAoGBAMAg6i83pNgSup2b+mnS\nWz7Eq7upNgFGI9HMOhMKuima2yJIlFt5n9aJr9o4SZSSno08LChtEtG3nnb1c0Pu\nH0kAvQKTHFPzWm7GAuKU3+A/ebYvlF/8POhNpXvKT4mk3He77vumwqnOF9W6tFzv\nuj2XcLdKMWE288t8Kpw1TTxa\n-----END PRIVATE KEY-----"
	//data of this^ specific certificate (after parsing)
	serialNumber   = "cb:d4:b6:ea:c8:6a:1b:5a"
	expirationDate = "2030-06-20T08:17:43Z"
	certCommonName = "domain.com"

	previousCert         = "-----BEGIN CERTIFICATE-----\nMIIFfjCCBGagAwIBAgITAPoY/qqz2E3RF0UL3WaBazTtITANBgkqhkiG9w0BAQsF\nADBZMQswCQYDVQQGEwJVUzEgMB4GA1UEChMXKFNUQUdJTkcpIExldCdzIEVuY3J5\ncHQxKDAmBgNVBAMTHyhTVEFHSU5HKSBBcnRpZmljaWFsIEFwcmljb3QgUjMwHhcN\nMjEwOTA2MDkzMDAyWhcNMjExMjA1MDkzMDAxWjAvMS0wKwYDVQQDEyRzZWNyZXRz\nLW1hbmFnZXIudGVzdC5hcHBkb21haW4uY2xvdWQwggEiMA0GCSqGSIb3DQEBAQUA\nA4IBDwAwggEKAoIBAQCd3dNlJcWvOsF8uwVlcw4zAGw9OBNYxwkO45tk1QMkJEil\nx7csMmVNaRxJNos3580hrqgjDDCAGiuSp79kIF/WSy/kDsZ7ZZwfCo5qhLh2r9Ju\nTxq8L2xYKzcKt2fvRGImhVGOW4qE4GCPrfWF/Zq/JvSCyr9BC1SLXWsxr5WssGx6\nmC53g3YLigLdYxsl+HLqA96FLE7/j8Ybh+ZmwBKqVRIGxzMP9KVg0EHdV1U9Mhwv\nJjjb7gXHJxOge5Xt2xzZ57o87+PBm4gOPOPSlWALi7KIFirsT79IF27+GKU0P3v5\naNwBOfx3fpwNpShCjUbGgM+4CmZRr9kY3anuLU1TAgMBAAGjggJnMIICYzAOBgNV\nHQ8BAf8EBAMCBaAwHQYDVR0lBBYwFAYIKwYBBQUHAwEGCCsGAQUFBwMCMAwGA1Ud\nEwEB/wQCMAAwHQYDVR0OBBYEFByIBVgihgUou/ahPoInE9JiXkjbMB8GA1UdIwQY\nMBaAFN5yekjfMcOmUN+fhSPfVzdLXS5lMF0GCCsGAQUFBwEBBFEwTzAlBggrBgEF\nBQcwAYYZaHR0cDovL3N0Zy1yMy5vLmxlbmNyLm9yZzAmBggrBgEFBQcwAoYaaHR0\ncDovL3N0Zy1yMy5pLmxlbmNyLm9yZy8wLwYDVR0RBCgwJoIkc2VjcmV0cy1tYW5h\nZ2VyLnRlc3QuYXBwZG9tYWluLmNsb3VkMEwGA1UdIARFMEMwCAYGZ4EMAQIBMDcG\nCysGAQQBgt8TAQEBMCgwJgYIKwYBBQUHAgEWGmh0dHA6Ly9jcHMubGV0c2VuY3J5\ncHQub3JnMIIBBAYKKwYBBAHWeQIEAgSB9QSB8gDwAHYAFuhpwdGV6tfD+Jca4/B2\nAfeM4badMahSGLaDfzGoFQgAAAF7uqhhEQAABAMARzBFAiBe392Bs19k/hVqBWeS\nfe/Fc7l7N9OFG/G2IrHOzoOnAQIhAKrJRKiySolV8N62lIUS+OoP2VpJs23MchjH\nzwiCwAnIAHYAKHYaGJAn++880NYaAY12sFBXKcenQRvMvfYE9F1CYVMAAAF7uqhk\n4gAABAMARzBFAiEAxK2Jdb1lTXU8frV2vkwdmaibivXXKvvV7OJpO0ncnNACIH37\n45k8T89OApmKq4MBPfjKGdnEah7Ufrmn7NO9+MGgMA0GCSqGSIb3DQEBCwUAA4IB\nAQAd7JOW/M0Yu/2fkIlYHW9bPydbYzIJNBi/QkIL3I63x4tKmAiFDGKiOxt1usbW\nQ16wpG7z1wvSFHwoUOm46POs0wLDaEEW6AQ38ld7tKOr4EP0h+tcgJqLGRxr/zIU\nhv7Qlok3JEtoEk2BG3ZnolC6NpZRwAuL77Kg/B7S6HiRpO1Q7DuWWKqQYOH0XjlH\nJapQRy8+9vpXTrrPUDuni2ehZtxIISu4qq2xjfYLBMX7FtDQL8r7s2iuChpqg/X+\nzcwHtHTUgFW5srtVsOYQ+fPNKv7jofBNSsoPFKixO1pPX0tjUgTMZfcvzck0EnwO\n4/6WSm7ncBUa+31/J0t1Uz2B\n-----END CERTIFICATE-----\n\n-----BEGIN CERTIFICATE-----\nMIIFWzCCA0OgAwIBAgIQTfQrldHumzpMLrM7jRBd1jANBgkqhkiG9w0BAQsFADBm\nMQswCQYDVQQGEwJVUzEzMDEGA1UEChMqKFNUQUdJTkcpIEludGVybmV0IFNlY3Vy\naXR5IFJlc2VhcmNoIEdyb3VwMSIwIAYDVQQDExkoU1RBR0lORykgUHJldGVuZCBQ\nZWFyIFgxMB4XDTIwMDkwNDAwMDAwMFoXDTI1MDkxNTE2MDAwMFowWTELMAkGA1UE\nBhMCVVMxIDAeBgNVBAoTFyhTVEFHSU5HKSBMZXQncyBFbmNyeXB0MSgwJgYDVQQD\nEx8oU1RBR0lORykgQXJ0aWZpY2lhbCBBcHJpY290IFIzMIIBIjANBgkqhkiG9w0B\nAQEFAAOCAQ8AMIIBCgKCAQEAu6TR8+74b46mOE1FUwBrvxzEYLck3iasmKrcQkb+\ngy/z9Jy7QNIAl0B9pVKp4YU76JwxF5DOZZhi7vK7SbCkK6FbHlyU5BiDYIxbbfvO\nL/jVGqdsSjNaJQTg3C3XrJja/HA4WCFEMVoT2wDZm8ABC1N+IQe7Q6FEqc8NwmTS\nnmmRQm4TQvr06DP+zgFK/MNubxWWDSbSKKTH5im5j2fZfg+j/tM1bGaczFWw8/lS\nnukyn5J2L+NJYnclzkXoh9nMFnyPmVbfyDPOc4Y25aTzVoeBKXa/cZ5MM+WddjdL\nbiWvm19f1sYn1aRaAIrkppv7kkn83vcth8XCG39qC2ZvaQIDAQABo4IBEDCCAQww\nDgYDVR0PAQH/BAQDAgGGMB0GA1UdJQQWMBQGCCsGAQUFBwMCBggrBgEFBQcDATAS\nBgNVHRMBAf8ECDAGAQH/AgEAMB0GA1UdDgQWBBTecnpI3zHDplDfn4Uj31c3S10u\nZTAfBgNVHSMEGDAWgBS182Xy/rAKkh/7PH3zRKCsYyXDFDA2BggrBgEFBQcBAQQq\nMCgwJgYIKwYBBQUHMAKGGmh0dHA6Ly9zdGcteDEuaS5sZW5jci5vcmcvMCsGA1Ud\nHwQkMCIwIKAeoByGGmh0dHA6Ly9zdGcteDEuYy5sZW5jci5vcmcvMCIGA1UdIAQb\nMBkwCAYGZ4EMAQIBMA0GCysGAQQBgt8TAQEBMA0GCSqGSIb3DQEBCwUAA4ICAQCN\nDLam9yN0EFxxn/3p+ruWO6n/9goCAM5PT6cC6fkjMs4uas6UGXJjr5j7PoTQf3C1\nvuxiIGRJC6qxV7yc6U0X+w0Mj85sHI5DnQVWN5+D1er7mp13JJA0xbAbHa3Rlczn\ny2Q82XKui8WHuWra0gb2KLpfboYj1Ghgkhr3gau83pC/WQ8HfkwcvSwhIYqTqxoZ\nUq8HIf3M82qS9aKOZE0CEmSyR1zZqQxJUT7emOUapkUN9poJ9zGc+FgRZvdro0XB\nyphWXDaqMYph0DxW/10ig5j4xmmNDjCRmqIKsKoWA52wBTKKXK1na2ty/lW5dhtA\nxkz5rVZFd4sgS4J0O+zm6d5GRkWsNJ4knotGXl8vtS3X40KXeb3A5+/3p0qaD215\nXq8oSNORfB2oI1kQuyEAJ5xvPTdfwRlyRG3lFYodrRg6poUBD/8fNTXMtzydpRgy\nzUQZh/18F6B/iW6cbiRN9r2Hkh05Om+q0/6w0DdZe+8YrNpfhSObr/1eVZbKGMIY\nqKmyZbBNu5ysENIK5MPc14mUeKmFjpN840VR5zunoU52lqpLDua/qIM8idk86xGW\nxx2ml43DO/Ya/tVZVok0mO0TUjzJIfPqyvr455IsIut4RlCR9Iq0EDTve2/ZwCuG\nhSjpTUFGSiQrR2JK2Evp+o6AETUkBCO1aw0PpQBPDQ==\n-----END CERTIFICATE-----\n\n-----BEGIN CERTIFICATE-----\nMIIFVDCCBDygAwIBAgIRAO1dW8lt+99NPs1qSY3Rs8cwDQYJKoZIhvcNAQELBQAw\ncTELMAkGA1UEBhMCVVMxMzAxBgNVBAoTKihTVEFHSU5HKSBJbnRlcm5ldCBTZWN1\ncml0eSBSZXNlYXJjaCBHcm91cDEtMCsGA1UEAxMkKFNUQUdJTkcpIERvY3RvcmVk\nIER1cmlhbiBSb290IENBIFgzMB4XDTIxMDEyMDE5MTQwM1oXDTI0MDkzMDE4MTQw\nM1owZjELMAkGA1UEBhMCVVMxMzAxBgNVBAoTKihTVEFHSU5HKSBJbnRlcm5ldCBT\nZWN1cml0eSBSZXNlYXJjaCBHcm91cDEiMCAGA1UEAxMZKFNUQUdJTkcpIFByZXRl\nbmQgUGVhciBYMTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBALbagEdD\nTa1QgGBWSYkyMhscZXENOBaVRTMX1hceJENgsL0Ma49D3MilI4KS38mtkmdF6cPW\nnL++fgehT0FbRHZgjOEr8UAN4jH6omjrbTD++VZneTsMVaGamQmDdFl5g1gYaigk\nkmx8OiCO68a4QXg4wSyn6iDipKP8utsE+x1E28SA75HOYqpdrk4HGxuULvlr03wZ\nGTIf/oRt2/c+dYmDoaJhge+GOrLAEQByO7+8+vzOwpNAPEx6LW+crEEZ7eBXih6V\nP19sTGy3yfqK5tPtTdXXCOQMKAp+gCj/VByhmIr+0iNDC540gtvV303WpcbwnkkL\nYC0Ft2cYUyHtkstOfRcRO+K2cZozoSwVPyB8/J9RpcRK3jgnX9lujfwA/pAbP0J2\nUPQFxmWFRQnFjaq6rkqbNEBgLy+kFL1NEsRbvFbKrRi5bYy2lNms2NJPZvdNQbT/\n2dBZKmJqxHkxCuOQFjhJQNeO+Njm1Z1iATS/3rts2yZlqXKsxQUzN6vNbD8KnXRM\nEeOXUYvbV4lqfCf8mS14WEbSiMy87GB5S9ucSV1XUrlTG5UGcMSZOBcEUpisRPEm\nQWUOTWIoDQ5FOia/GI+Ki523r2ruEmbmG37EBSBXdxIdndqrjy+QVAmCebyDx9eV\nEGOIpn26bW5LKerumJxa/CFBaKi4bRvmdJRLAgMBAAGjgfEwge4wDgYDVR0PAQH/\nBAQDAgEGMA8GA1UdEwEB/wQFMAMBAf8wHQYDVR0OBBYEFLXzZfL+sAqSH/s8ffNE\noKxjJcMUMB8GA1UdIwQYMBaAFAhX2onHolN5DE/d4JCPdLriJ3NEMDgGCCsGAQUF\nBwEBBCwwKjAoBggrBgEFBQcwAoYcaHR0cDovL3N0Zy1kc3QzLmkubGVuY3Iub3Jn\nLzAtBgNVHR8EJjAkMCKgIKAehhxodHRwOi8vc3RnLWRzdDMuYy5sZW5jci5vcmcv\nMCIGA1UdIAQbMBkwCAYGZ4EMAQIBMA0GCysGAQQBgt8TAQEBMA0GCSqGSIb3DQEB\nCwUAA4IBAQB7tR8B0eIQSS6MhP5kuvGth+dN02DsIhr0yJtk2ehIcPIqSxRRmHGl\n4u2c3QlvEpeRDp2w7eQdRTlI/WnNhY4JOofpMf2zwABgBWtAu0VooQcZZTpQruig\nF/z6xYkBk3UHkjeqxzMN3d1EqGusxJoqgdTouZ5X5QTTIee9nQ3LEhWnRSXDx7Y0\nttR1BGfcdqHopO4IBqAhbkKRjF5zj7OD8cG35omywUbZtOJnftiI0nFcRaxbXo0v\noDfLD0S6+AC2R3tKpqjkNX6/91hrRFglUakyMcZU/xleqbv6+Lr3YD8PsBTub6lI\noZ2lS38fL18Aon458fbc0BPHtenfhKj5\n-----END CERTIFICATE-----\n"
	previousIntermediate = "-----BEGIN CERTIFICATE-----\nMIIFWzCCA0OgAwIBAgIQTfQrldHumzpMLrM7jRBd1jANBgkqhkiG9w0BAQsFADBm\nMQswCQYDVQQGEwJVUzEzMDEGA1UEChMqKFNUQUdJTkcpIEludGVybmV0IFNlY3Vy\naXR5IFJlc2VhcmNoIEdyb3VwMSIwIAYDVQQDExkoU1RBR0lORykgUHJldGVuZCBQ\nZWFyIFgxMB4XDTIwMDkwNDAwMDAwMFoXDTI1MDkxNTE2MDAwMFowWTELMAkGA1UE\nBhMCVVMxIDAeBgNVBAoTFyhTVEFHSU5HKSBMZXQncyBFbmNyeXB0MSgwJgYDVQQD\nEx8oU1RBR0lORykgQXJ0aWZpY2lhbCBBcHJpY290IFIzMIIBIjANBgkqhkiG9w0B\nAQEFAAOCAQ8AMIIBCgKCAQEAu6TR8+74b46mOE1FUwBrvxzEYLck3iasmKrcQkb+\ngy/z9Jy7QNIAl0B9pVKp4YU76JwxF5DOZZhi7vK7SbCkK6FbHlyU5BiDYIxbbfvO\nL/jVGqdsSjNaJQTg3C3XrJja/HA4WCFEMVoT2wDZm8ABC1N+IQe7Q6FEqc8NwmTS\nnmmRQm4TQvr06DP+zgFK/MNubxWWDSbSKKTH5im5j2fZfg+j/tM1bGaczFWw8/lS\nnukyn5J2L+NJYnclzkXoh9nMFnyPmVbfyDPOc4Y25aTzVoeBKXa/cZ5MM+WddjdL\nbiWvm19f1sYn1aRaAIrkppv7kkn83vcth8XCG39qC2ZvaQIDAQABo4IBEDCCAQww\nDgYDVR0PAQH/BAQDAgGGMB0GA1UdJQQWMBQGCCsGAQUFBwMCBggrBgEFBQcDATAS\nBgNVHRMBAf8ECDAGAQH/AgEAMB0GA1UdDgQWBBTecnpI3zHDplDfn4Uj31c3S10u\nZTAfBgNVHSMEGDAWgBS182Xy/rAKkh/7PH3zRKCsYyXDFDA2BggrBgEFBQcBAQQq\nMCgwJgYIKwYBBQUHMAKGGmh0dHA6Ly9zdGcteDEuaS5sZW5jci5vcmcvMCsGA1Ud\nHwQkMCIwIKAeoByGGmh0dHA6Ly9zdGcteDEuYy5sZW5jci5vcmcvMCIGA1UdIAQb\nMBkwCAYGZ4EMAQIBMA0GCysGAQQBgt8TAQEBMA0GCSqGSIb3DQEBCwUAA4ICAQCN\nDLam9yN0EFxxn/3p+ruWO6n/9goCAM5PT6cC6fkjMs4uas6UGXJjr5j7PoTQf3C1\nvuxiIGRJC6qxV7yc6U0X+w0Mj85sHI5DnQVWN5+D1er7mp13JJA0xbAbHa3Rlczn\ny2Q82XKui8WHuWra0gb2KLpfboYj1Ghgkhr3gau83pC/WQ8HfkwcvSwhIYqTqxoZ\nUq8HIf3M82qS9aKOZE0CEmSyR1zZqQxJUT7emOUapkUN9poJ9zGc+FgRZvdro0XB\nyphWXDaqMYph0DxW/10ig5j4xmmNDjCRmqIKsKoWA52wBTKKXK1na2ty/lW5dhtA\nxkz5rVZFd4sgS4J0O+zm6d5GRkWsNJ4knotGXl8vtS3X40KXeb3A5+/3p0qaD215\nXq8oSNORfB2oI1kQuyEAJ5xvPTdfwRlyRG3lFYodrRg6poUBD/8fNTXMtzydpRgy\nzUQZh/18F6B/iW6cbiRN9r2Hkh05Om+q0/6w0DdZe+8YrNpfhSObr/1eVZbKGMIY\nqKmyZbBNu5ysENIK5MPc14mUeKmFjpN840VR5zunoU52lqpLDua/qIM8idk86xGW\nxx2ml43DO/Ya/tVZVok0mO0TUjzJIfPqyvr455IsIut4RlCR9Iq0EDTve2/ZwCuG\nhSjpTUFGSiQrR2JK2Evp+o6AETUkBCO1aw0PpQBPDQ==\n-----END CERTIFICATE-----\n\n-----BEGIN CERTIFICATE-----\nMIIFVDCCBDygAwIBAgIRAO1dW8lt+99NPs1qSY3Rs8cwDQYJKoZIhvcNAQELBQAw\ncTELMAkGA1UEBhMCVVMxMzAxBgNVBAoTKihTVEFHSU5HKSBJbnRlcm5ldCBTZWN1\ncml0eSBSZXNlYXJjaCBHcm91cDEtMCsGA1UEAxMkKFNUQUdJTkcpIERvY3RvcmVk\nIER1cmlhbiBSb290IENBIFgzMB4XDTIxMDEyMDE5MTQwM1oXDTI0MDkzMDE4MTQw\nM1owZjELMAkGA1UEBhMCVVMxMzAxBgNVBAoTKihTVEFHSU5HKSBJbnRlcm5ldCBT\nZWN1cml0eSBSZXNlYXJjaCBHcm91cDEiMCAGA1UEAxMZKFNUQUdJTkcpIFByZXRl\nbmQgUGVhciBYMTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBALbagEdD\nTa1QgGBWSYkyMhscZXENOBaVRTMX1hceJENgsL0Ma49D3MilI4KS38mtkmdF6cPW\nnL++fgehT0FbRHZgjOEr8UAN4jH6omjrbTD++VZneTsMVaGamQmDdFl5g1gYaigk\nkmx8OiCO68a4QXg4wSyn6iDipKP8utsE+x1E28SA75HOYqpdrk4HGxuULvlr03wZ\nGTIf/oRt2/c+dYmDoaJhge+GOrLAEQByO7+8+vzOwpNAPEx6LW+crEEZ7eBXih6V\nP19sTGy3yfqK5tPtTdXXCOQMKAp+gCj/VByhmIr+0iNDC540gtvV303WpcbwnkkL\nYC0Ft2cYUyHtkstOfRcRO+K2cZozoSwVPyB8/J9RpcRK3jgnX9lujfwA/pAbP0J2\nUPQFxmWFRQnFjaq6rkqbNEBgLy+kFL1NEsRbvFbKrRi5bYy2lNms2NJPZvdNQbT/\n2dBZKmJqxHkxCuOQFjhJQNeO+Njm1Z1iATS/3rts2yZlqXKsxQUzN6vNbD8KnXRM\nEeOXUYvbV4lqfCf8mS14WEbSiMy87GB5S9ucSV1XUrlTG5UGcMSZOBcEUpisRPEm\nQWUOTWIoDQ5FOia/GI+Ki523r2ruEmbmG37EBSBXdxIdndqrjy+QVAmCebyDx9eV\nEGOIpn26bW5LKerumJxa/CFBaKi4bRvmdJRLAgMBAAGjgfEwge4wDgYDVR0PAQH/\nBAQDAgEGMA8GA1UdEwEB/wQFMAMBAf8wHQYDVR0OBBYEFLXzZfL+sAqSH/s8ffNE\noKxjJcMUMB8GA1UdIwQYMBaAFAhX2onHolN5DE/d4JCPdLriJ3NEMDgGCCsGAQUF\nBwEBBCwwKjAoBggrBgEFBQcwAoYcaHR0cDovL3N0Zy1kc3QzLmkubGVuY3Iub3Jn\nLzAtBgNVHR8EJjAkMCKgIKAehhxodHRwOi8vc3RnLWRzdDMuYy5sZW5jci5vcmcv\nMCIGA1UdIAQbMBkwCAYGZ4EMAQIBMA0GCysGAQQBgt8TAQEBMA0GCSqGSIb3DQEB\nCwUAA4IBAQB7tR8B0eIQSS6MhP5kuvGth+dN02DsIhr0yJtk2ehIcPIqSxRRmHGl\n4u2c3QlvEpeRDp2w7eQdRTlI/WnNhY4JOofpMf2zwABgBWtAu0VooQcZZTpQruig\nF/z6xYkBk3UHkjeqxzMN3d1EqGusxJoqgdTouZ5X5QTTIee9nQ3LEhWnRSXDx7Y0\nttR1BGfcdqHopO4IBqAhbkKRjF5zj7OD8cG35omywUbZtOJnftiI0nFcRaxbXo0v\noDfLD0S6+AC2R3tKpqjkNX6/91hrRFglUakyMcZU/xleqbv6+Lr3YD8PsBTub6lI\noZ2lS38fL18Aon458fbc0BPHtenfhKj5\n-----END CERTIFICATE-----\n"
	previousPrivKey      = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEAnd3TZSXFrzrBfLsFZXMOMwBsPTgTWMcJDuObZNUDJCRIpce3\nLDJlTWkcSTaLN+fNIa6oIwwwgBorkqe/ZCBf1ksv5A7Ge2WcHwqOaoS4dq/Sbk8a\nvC9sWCs3Crdn70RiJoVRjluKhOBgj631hf2avyb0gsq/QQtUi11rMa+VrLBsepgu\nd4N2C4oC3WMbJfhy6gPehSxO/4/GG4fmZsASqlUSBsczD/SlYNBB3VdVPTIcLyY4\n2+4FxycToHuV7dsc2ee6PO/jwZuIDjzj0pVgC4uyiBYq7E+/SBdu/hilND97+Wjc\nATn8d36cDaUoQo1GxoDPuApmUa/ZGN2p7i1NUwIDAQABAoIBAG5uAbY7mfFd1IN/\n/+JbfY9HuG+Kjl4HvNphdQ4vw6bAiuEMt6F/D0X7RQIh2Xkd+WyaVJtPp420wM4x\n8bwEuYWZysJpY4ZmKbO9GqqAdNjxXO40/6qsMcnrUPF6IoZI+6+eitJeTqNsoZ9g\nPOOh52HXyirD0M2bM2TZ0GZNQRIurhO42tFw7mSFWuouSxpaxfqH5oTei/Ld4x5b\nrsPHnaYv7QxiZ78qHtMbS9MxVn4sgs4E+M4biK417y7zDqzVJWB3+lnchgqVA84z\nD/YAg7bA/CRP/5Gt0QIyuQ0zuG2/nPzevpn7mman1yCFOMH8PEzyWcRuRWm7ijFw\n698JIEECgYEAwzjlUur3AAwgYVpUPUggOzotjioiDCf4yItUkVrF/vW10ZgBw7H9\ndiUFv+eEHhWshTb1lw8YJc50j2qljtH0rNb8zo03jDpQo4RmoR3gCJl/+e72y21e\n5st3P3dBcW5JGXIPyLA6otqZzTU5tc4TivoQQjAEU9Kaq+1hjqJypokCgYEAzwOy\nu1OooNqDkR6UyjTsssbVWPknsjobPAmVm2j+3xIGaA5ekvw1yG7/QBkWjQqZ+kOT\nynU6tYtjv+74xkQyR8YtRFo+fwZNyHzuxixc7HUI9R+FbgFbSXch5gonP2FQOtV1\n6jw8A6BpE1PT3Rgs0Nr9A0CL27oc8zNrUxISnfsCgYEAqmQRfGLKfUcYSABgQDCg\nuTEZK9lIaFXHBbrecBPLdrIdJLfI6naC5EiCETJQFTYTox4KEvPAvtbI05hgshw8\ns1LdyqZlEkaftWjNbti1fqwDkDDrRTjLuSNjjIhZHVkGAmiUsDRoqVWlIf/PxAf+\n9LE32Z0xWbwa9e611Jmi+gkCgYBPyJMX01RIOi8+vNSHYgJfnHYZRl1gOTjJ2L/K\nF5szCdViQTd92qo3x1+kqoagcReK9oR9INUxprkY/dbvQtVGCEDl+QnhFuLfhBba\nVbqyfyCmqDFahjdShxGPgRZDPRQYuLArSG+wzh/xDPu4WFrdW6jrmfLNCluh941D\nhNGcBQKBgEffQcdK3DLwUF3/tVMlf/Y+1QqzobikaRE3uu5uOyPrrJI313MBj4/l\n2Ud8ppXLs2wCG9x7KC7e8aSzxsipWydl0cOMkU67wSO6MLjEZQnPisQiaazCJfI8\nG+Da0I4euW7oxK2+lU95ZausHII30x9TxJGE62W6jf3LdZOfIGB1\n-----END RSA PRIVATE KEY-----\n"

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
		assert.Equal(t, resp.Data[secretentry.FieldStateDescription], secret_metadata_entry.GetNistStateDescription(secretentry.StateActive))
		assert.Equal(t, resp.Data[secretentry.FieldCreatedBy], createdBy)
		//specific fields
		assert.Equal(t, resp.Data[secretentry.FieldKeyAlgorithm], keyType)
		assert.Equal(t, resp.Data[secretentry.FieldCommonName], certCommonName)
		assert.Equal(t, true, reflect.DeepEqual(resp.Data[secretentry.FieldAltNames].([]string), []string{}))
		assert.DeepEqual(t, resp.Data[secretentry.FieldSecretData], expectedSecretData)
		//issuance info
		assert.Equal(t, resp.Data[FieldIssuanceInfo].(map[string]interface{})[FieldAutoRotated], false)
		assert.Equal(t, resp.Data[FieldIssuanceInfo].(map[string]interface{})[FieldBundleCert], false)
		assert.Equal(t, resp.Data[FieldIssuanceInfo].(map[string]interface{})[FieldCAConfig], caConfig)
		assert.Equal(t, resp.Data[FieldIssuanceInfo].(map[string]interface{})[FieldDNSConfig], dnsConfig)
		assert.Equal(t, resp.Data[FieldIssuanceInfo].(map[string]interface{})[secretentry.FieldStateDescription], secret_metadata_entry.GetNistStateDescription(secretentry.StateActive))
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
		assert.Equal(t, resp.Data[secretentry.FieldStateDescription], secret_metadata_entry.GetNistStateDescription(secretentry.StateDeactivated))
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
		assert.Equal(t, resp.Data[FieldIssuanceInfo].(map[string]interface{})[secretentry.FieldStateDescription], secret_metadata_entry.GetNistStateDescription(secretentry.StateDeactivated))
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
		assert.Equal(t, resp.Data[secretentry.FieldStateDescription], secret_metadata_entry.GetNistStateDescription(secretentry.StateActive))
		assert.Equal(t, resp.Data[secretentry.FieldCreatedBy], createdBy)
		//specific fields
		assert.Equal(t, resp.Data[secretentry.FieldKeyAlgorithm], keyType)
		assert.Equal(t, resp.Data[secretentry.FieldCommonName], certCommonName)
		assert.Equal(t, true, reflect.DeepEqual(resp.Data[secretentry.FieldAltNames].([]string), []string{}))
		assert.DeepEqual(t, resp.Data[secretentry.FieldSecretData], expectedSecretData)
		//issuance info
		assert.Equal(t, resp.Data[FieldIssuanceInfo].(map[string]interface{})[FieldAutoRotated], false)
		assert.Equal(t, resp.Data[FieldIssuanceInfo].(map[string]interface{})[FieldBundleCert], bundleCerts)
		assert.Equal(t, resp.Data[FieldIssuanceInfo].(map[string]interface{})[FieldCAConfig], caConfig)
		assert.Equal(t, resp.Data[FieldIssuanceInfo].(map[string]interface{})[FieldDNSConfig], dnsConfig)
		assert.Equal(t, resp.Data[FieldIssuanceInfo].(map[string]interface{})[secretentry.FieldStateDescription], secret_metadata_entry.GetNistStateDescription(secretentry.StateActive))
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
		assert.Equal(t, resp.Data[secretentry.FieldStateDescription], secret_metadata_entry.GetNistStateDescription(secretentry.StateActive))
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
		assert.Equal(t, resp.Data[FieldIssuanceInfo].(map[string]interface{})[secretentry.FieldStateDescription], secret_metadata_entry.GetNistStateDescription(secretentry.StateDeactivated))
		//versions
		assert.Equal(t, resp.Data[secretentry.FieldVersionsTotal], 1)
		checkOrdersInProgress(t, []OrderDetails{})
	})

	t.Run("First order - order succeeded, but parsing failed", func(t *testing.T) {
		badParserHandler := &OrdersHandler{
			runningOrders:  make(map[string]WorkItem),
			beforeOrders:   make(map[string]WorkItem),
			parser:         &parserMock{},
			metadataMapper: secret_backend.GetDefaultMetadataMapper(secretentry.SecretTypePublicCert),
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
		assert.Equal(t, resp.Data[secretentry.FieldStateDescription], secret_metadata_entry.GetNistStateDescription(secretentry.StateDeactivated))
		assert.Equal(t, resp.Data[secretentry.FieldCreatedBy], createdBy)
		//issuance info
		assert.Equal(t, resp.Data[FieldIssuanceInfo].(map[string]interface{})[FieldAutoRotated], false)
		assert.Equal(t, resp.Data[FieldIssuanceInfo].(map[string]interface{})[FieldBundleCert], false)
		assert.Equal(t, resp.Data[FieldIssuanceInfo].(map[string]interface{})[FieldCAConfig], caConfig)
		assert.Equal(t, resp.Data[FieldIssuanceInfo].(map[string]interface{})[FieldDNSConfig], dnsConfig)
		assert.Equal(t, resp.Data[FieldIssuanceInfo].(map[string]interface{})[FieldErrorCode], logdna.Error07063)
		assert.Equal(t, resp.Data[FieldIssuanceInfo].(map[string]interface{})[FieldErrorMessage], failedToParseCertificate)
		assert.Equal(t, resp.Data[FieldIssuanceInfo].(map[string]interface{})[secretentry.FieldStateDescription], secret_metadata_entry.GetNistStateDescription(secretentry.StateDeactivated))
		checkOrdersInProgress(t, []OrderDetails{{GroupId: defaultGroup, Id: "1", Attempts: 1}}) //only the second of 2
	})

}

func createOrderResult(withError bool, bundleCert bool, rotation bool) Result {
	certMetadata := certificate.CertificateMetadata{
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
				SecretMetadataEntry: secret_metadata_entry.SecretMetadataEntry{
					ID:             secretId,
					Name:           certName1,
					Description:    certDesc,
					Labels:         labels,
					ExtraData:      certMetadata,
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
				Versions: versions,
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
