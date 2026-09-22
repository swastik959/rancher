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
	"sigs.k8s.io/aws-iam-authenticator/pkg/endpoints"
)

const (
	defaultAWSRegion      = "us-east-1"
	defaultUSGovAWSRegion = "us-gov-west-1"
	cnNorth1AWSRegion     = "cn-north-1"
	cnNorthwest1AWSRegion = "cn-northwest-1"
)

// awsRegionRegexp matches AWS region names such as "us-east-1", "cn-northwest-1", "us-gov-west-1"
// or "eusc-de-east-1". It generalizes the per partition regionRegex entries of the AWS partition
// metadata, which the v2 SDK only ships in internal packages.
var awsRegionRegexp = regexp.MustCompile(`^[a-z]{2,4}(-[a-z]+)+-\d+$`)

// awsEndpointLabels are the hostname labels that AWS endpoints carry next to the service name,
// for instance to flag FIPS, dual stack or VPC endpoints. They are never a service name.
var awsEndpointLabels = map[string]bool{
	"api":       true,
	"dualstack": true,
	"fips":      true,
	"global":    true,
	"us-gov":    true,
	"vpce":      true,
}

// awsPartitionDNSSuffixes holds the DNS suffixes of every known AWS partition, longest first so
// that the most specific suffix of a host is always matched first.
var awsPartitionDNSSuffixes = partitionDNSSuffixes()

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

// getServiceAndRegion derives the SigV4 signing service and region from the host of the endpoint
// the request is proxied to.
func (a awsv4) getServiceAndRegion(host string) (string, string) {
	service, region := parseEndpointHost(host)

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

// parseEndpointHost splits an AWS endpoint host into its service name and its region, returning an
// empty region for global endpoints and empty values for hosts that do not look like an AWS
// endpoint.
//
// The partition and endpoint metadata that the v1 aws/endpoints package exposed has no equivalent
// in the AWS SDK for Go v2, where it is only reachable through internal SDK packages. The values
// are therefore derived from the structure of the endpoint host itself, which AWS documents as
// the service name, an optional region and the DNS suffix of the partition, plus optional labels
// such as "fips" or "dualstack":
//
//	ec2.us-west-2.amazonaws.com                 -> ec2, us-west-2
//	iam.amazonaws.com                           -> iam, ""
//	bucket.s3.dualstack.eu-west-1.amazonaws.com -> s3, eu-west-1
//	s3-us-west-2.amazonaws.com                  -> s3, us-west-2
func parseEndpointHost(host string) (string, string) {
	labels := endpointLabels(host)
	for i := len(labels) - 1; i >= 0; i-- {
		if isAWSRegion(labels[i]) {
			return endpointService(labels, i), labels[i]
		}
		// Older style endpoints join the service name and the region in a single label.
		if service, region, ok := splitServiceRegion(labels[i]); ok {
			return service, region
		}
	}
	return endpointService(labels, len(labels)), ""
}

// endpointLabels strips the port and the DNS suffix of the partition from the given host and
// returns the remaining hostname labels.
func endpointLabels(host string) []string {
	if hostWithoutPort, _, err := net.SplitHostPort(host); err == nil {
		host = hostWithoutPort
	}
	host = strings.ToLower(strings.TrimSuffix(host, "."))

	for _, suffix := range awsPartitionDNSSuffixes {
		if trimmed, found := strings.CutSuffix(host, "."+suffix); found {
			return strings.Split(trimmed, ".")
		}
	}

	// The host does not belong to a known partition, it can still be an AWS endpoint of a
	// partition added after this list was built, or an AWS compatible endpoint hosted elsewhere.
	// Drop the two labels of its domain and parse the rest as an endpoint host.
	labels := strings.Split(host, ".")
	if len(labels) <= 2 {
		return nil
	}
	return labels[:len(labels)-2]
}

// endpointService returns the service name of an endpoint from its labels and the position of its
// region label, which is len(labels) for endpoints without a region. The service name usually
// precedes the region, but some endpoints, such as the EKS cluster endpoints, place it after.
func endpointService(labels []string, regionIndex int) string {
	if service := firstServiceLabel(labels[min(regionIndex+1, len(labels)):]); service != "" {
		return service
	}

	beforeRegion := slices.Clone(labels[:min(regionIndex, len(labels))])
	slices.Reverse(beforeRegion)
	return firstServiceLabel(beforeRegion)
}

// firstServiceLabel returns the first of the given labels that can be a service name, skipping the
// labels AWS adds to endpoint hosts around the service name.
func firstServiceLabel(labels []string) string {
	for _, label := range labels {
		if awsEndpointLabels[label] {
			continue
		}
		return strings.TrimSuffix(label, "-fips")
	}
	return ""
}

// isAWSRegion reports whether the given hostname label is an AWS region name.
func isAWSRegion(label string) bool {
	if !awsRegionRegexp.MatchString(label) {
		return false
	}
	// Labels such as "fips-us-gov-west-1" carry an endpoint modifier and are not a region name.
	prefix, _, _ := strings.Cut(label, "-")
	return !awsEndpointLabels[prefix]
}

// splitServiceRegion splits a hostname label that joins the service name and the region, as the
// older style AWS endpoints do, for instance "s3-us-west-2" or "s3-fips-us-gov-west-1".
func splitServiceRegion(label string) (string, string, bool) {
	for i, char := range label {
		if char != '-' {
			continue
		}
		if region := label[i+1:]; isAWSRegion(region) {
			return strings.TrimSuffix(label[:i], "-fips"), region, true
		}
	}
	return "", "", false
}

// partitionDNSSuffixes returns the DNS suffixes of all the known AWS partitions. The partition
// metadata of the v2 SDK is internal to it, so the copy that the aws-iam-authenticator project
// maintains for the same reason is reused here rather than duplicating the data once more.
func partitionDNSSuffixes() []string {
	suffixes := make([]string, 0, 2*len(endpoints.PARTITIONS))
	for _, partition := range endpoints.PARTITIONS {
		domain, err := endpoints.GetSTSPartitionDomain(partition)
		if err != nil {
			// Only returned for unknown partitions, which the listed ones are not.
			continue
		}
		suffixes = append(suffixes, domain)

		if dualStackDomain := endpoints.GetSTSDualStackPartitionDomain(partition); dualStackDomain != "" {
			suffixes = append(suffixes, dualStackDomain)
		}
	}

	slices.Sort(suffixes)
	suffixes = slices.Compact(suffixes)
	// Longest first, so that for instance "amazonaws.com.cn" is matched before "amazonaws.com".
	slices.SortStableFunc(suffixes, func(a, b string) int { return len(b) - len(a) })

	return suffixes
}
