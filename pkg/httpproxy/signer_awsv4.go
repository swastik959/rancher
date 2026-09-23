package httpproxy

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"regexp"
	"slices"
	"strings"
	"time"

	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/aws/aws-sdk-go-v2/credentials"
)

const (
	defaultAWSRegion      = "us-east-1"
	defaultUSGovAWSRegion = "us-gov-west-1"
	cnNorth1AWSRegion     = "cn-north-1"
	cnNorthwest1AWSRegion = "cn-northwest-1"
)

// List of global services for AWS from: https://docs.aws.amazon.com/general/latest/gr/rande.html#global-endpoints
var globalAWSServices = []string{"cloudfront", "globalaccelerator", "iam", "networkmanager", "organizations", "route53", "shield", "waf"}

// awsDNSSuffixes are the DNS suffixes of the AWS partitions, taken from the endpoints
// metadata (partitions.json) that used to be exposed by github.com/aws/aws-sdk-go/aws/endpoints.
//
// V2 Migration Workaround: aws-sdk-go-v2 dropped the aws/endpoints package. Endpoints are now
// resolved by per-service rule engines (aws.EndpointResolverWithOptions and, more recently, the
// service specific EndpointResolverV2 implementations), all of which only resolve in the forward
// direction, from a service and a region to a hostname. Signing a request that is proxied on
// behalf of the UI requires the opposite, so we keep the minimal subset of the partition metadata
// needed to map a hostname back to its service and region.
//
// The suffixes are ordered from the most specific to the least specific one so that hosts such as
// "ec2.cn-north-1.amazonaws.com.cn" are not matched against "amazonaws.com".
var awsDNSSuffixes = []string{
	"api.amazonwebservices.com.cn", // aws-cn, dual-stack
	"amazonaws.com.cn",             // aws-cn
	"csp.hci.ic.gov",               // aws-iso-f
	"cloud.adc-e.uk",               // aws-iso-e
	"sc2s.sgov.gov",                // aws-iso-b
	"c2s.ic.gov",                   // aws-iso
	"amazonaws.com",                // aws and aws-us-gov
	"amazonaws.eu",                 // aws-eusc
	"api.aws",                      // aws, dual-stack
}

// awsRegionRegexp matches the region identifiers of every AWS partition, for example "us-east-1",
// "cn-northwest-1", "us-gov-west-1", "us-iso-east-1" or "eusc-de-east-1". It mirrors the region
// regular expressions of the partition metadata described above.
var awsRegionRegexp = regexp.MustCompile(`^[a-z]{2,}(-[a-z0-9]+)+-\d+$`)

// awsNonServiceLabels are hostname labels that are part of an endpoint but never identify the
// service that the request must be signed for, e.g. "s3.dualstack.us-east-1.amazonaws.com",
// "iam.us-gov.amazonaws.com" or "vpce-0123.ec2.us-east-1.vpce.amazonaws.com".
var awsNonServiceLabels = []string{"api", "dualstack", "fips", "us-gov", "vpce"}

func (a awsv4) getServiceAndRegion(host string) (string, string) {
	service, region := parseAWSEndpoint(host)

	// Some services are global and don't have a region. Requests to them are signed with the
	// default region of their partition even when the hostname is regional, e.g. the FIPS
	// endpoint "iam-fips.us-east-1.amazonaws.com" is signed for the "us-east-1" region in the
	// aws partition and for "us-gov-west-1" in the aws-us-gov partition.
	if slices.Contains(globalAWSServices, service) {
		region = ""
	}

	// empty region is valid, but if one is found it should be assumed correct
	if region != "" {
		return service, region
	}

	if strings.EqualFold(service, "iam") {
		// This conditional is meant to cover a discrepancy in the IAM service for the China regions.
		// The following doc states that IAM uses a globally unique endpoint, and the default
		// region "us-east-1" should be used as part of the Credential authentication parameter
		// (Current backend behavior). However, using "us-east-1" with any of the China regions will throw
		// the error "SignatureDoesNotMatch: Credential should be scoped to a valid region, not 'us-east-1'.".
		// https://docs.aws.amazon.com/general/latest/gr/sigv4_elements.html
		//
		// This other doc states the region value for China services should be "cn-north-1" or "cn-northwest-1"
		// including IAM (See IAM endpoints in the tables). So they need to be set manually to prevent the error
		// caused by the "us-east-1" default.
		// https://docs.amazonaws.cn/en_us/aws/latest/userguide/endpoints-Beijing.html
		if strings.Contains(host, cnNorth1AWSRegion) {
			return service, cnNorth1AWSRegion
		}
		if strings.Contains(host, cnNorthwest1AWSRegion) {
			return service, cnNorthwest1AWSRegion
		}
	}
	// if no region is found, global endpoint is assumed.
	// https://docs.aws.amazon.com/general/latest/gr/sigv4_elements.html
	if strings.Contains(host, "us-gov") {
		return service, defaultUSGovAWSRegion
	}

	return service, defaultAWSRegion
}

// parseAWSEndpoint maps an AWS endpoint hostname back to the service and the region it belongs to.
// Both values are empty when the host isn't part of a known AWS partition, and the region is empty
// for global endpoints such as "iam.amazonaws.com".
func parseAWSEndpoint(host string) (string, string) {
	host = strings.ToLower(host)
	if hostname, _, err := net.SplitHostPort(host); err == nil {
		host = hostname
	}
	host = strings.TrimSuffix(host, ".")

	labels, ok := trimAWSDNSSuffix(host)
	if !ok || len(labels) == 0 {
		return "", ""
	}

	// AWS endpoints are made of a service and, unless the service is global, a region, e.g.
	// "ec2.us-east-1.amazonaws.com". Both can be preceded and followed by additional labels, e.g.
	// "123456789012.dkr.ecr.us-east-1.amazonaws.com" or "mydb.abc.us-east-1.rds.amazonaws.com".
	regionIndex := -1
	for i := len(labels) - 1; i >= 0; i-- {
		if awsRegionRegexp.MatchString(labels[i]) {
			regionIndex = i
			break
		}
	}

	if regionIndex < 0 {
		// Global endpoints are named after the service they serve, e.g. "iam.amazonaws.com",
		// "mybucket.s3.amazonaws.com" or "iam.us-gov.amazonaws.com".
		for i := len(labels) - 1; i >= 0; i-- {
			if service := awsServiceLabel(labels[i]); service != "" {
				return service, ""
			}
		}
		return "", ""
	}

	// Data plane endpoints are suffixed with the service, e.g. "mydb.abc.us-east-1.rds.amazonaws.com",
	// while control plane endpoints are prefixed with it, e.g. "ec2.us-east-1.amazonaws.com".
	for i := len(labels) - 1; i > regionIndex; i-- {
		if service := awsServiceLabel(labels[i]); service != "" {
			return service, labels[regionIndex]
		}
	}
	for i := regionIndex - 1; i >= 0; i-- {
		if service := awsServiceLabel(labels[i]); service != "" {
			return service, labels[regionIndex]
		}
	}

	return "", labels[regionIndex]
}

// trimAWSDNSSuffix splits the host into its labels once the DNS suffix of its partition has been
// removed. It reports false when the host doesn't belong to any known AWS partition.
func trimAWSDNSSuffix(host string) ([]string, bool) {
	for _, suffix := range awsDNSSuffixes {
		if trimmed, ok := strings.CutSuffix(host, "."+suffix); ok {
			return strings.Split(trimmed, "."), true
		}
	}
	return nil, false
}

// awsServiceLabel returns the signing service name held by a hostname label, or an empty string if
// the label doesn't identify a service. FIPS endpoints are signed with the name of the service they
// front, so the "-fips" marker is dropped, e.g. "ec2-fips.us-east-1.amazonaws.com" signs for "ec2".
func awsServiceLabel(label string) string {
	label = strings.TrimSuffix(label, "-fips")
	if label == "" || slices.Contains(awsNonServiceLabels, label) {
		return ""
	}
	return label
}

var requiredHeadersForAws = map[string]bool{"host": true,
	"x-amz-content-sha256": true,
	"x-amz-date":           true,
	"x-amz-user-agent":     true}

func (a awsv4) sign(req *http.Request, secrets SecretGetter, auth string) error {
	_, secret, err := getAuthData(auth, secrets, []string{"credID"})
	if err != nil {
		return err
	}
	service, region := a.getServiceAndRegion(req.URL.Host)
	credentialProvider := credentials.NewStaticCredentialsProvider(secret["accessKey"], secret["secretKey"], "")
	awsSigner := v4.NewSigner()
	var body []byte
	if req.Body != nil {
		body, err = io.ReadAll(req.Body)
		if err != nil {
			return fmt.Errorf("error reading request body %v", err)
		}
	}

	h := sha256.New()
	h.Write(body)
	payloadHash := hex.EncodeToString(h.Sum(nil))

	oldHeader, newHeader := http.Header{}, http.Header{}
	for header, value := range req.Header {
		if _, ok := requiredHeadersForAws[strings.ToLower(header)]; ok {
			newHeader[header] = value
		} else {
			oldHeader[header] = value
		}
	}
	req.Header = newHeader
	err = awsSigner.SignHTTP(req.Context(), credentialProvider.Value, req, payloadHash, service, region, time.Now())
	if err != nil {
		return err
	}

	// The V2 SDK does not implement internally the sign with body method as per https://github.com/aws/aws-sdk-go/blob/main/aws/signer/v4/v4.go#L357
	// Therefore we need the below in order for the body to be included with the forwarded request.

	var (
		reader     io.ReadCloser
		ok         bool
		bodyReader io.ReadSeeker = bytes.NewReader(body)
	)
	if reader, ok = bodyReader.(io.ReadCloser); !ok {
		reader = io.NopCloser(bodyReader)
	}
	req.Body = reader

	for key, val := range oldHeader {
		req.Header.Add(key, strings.Join(val, ""))
	}
	return nil
}
