package httpproxy

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

var TestCases = []struct{ host, service, region string }{
	{"ec2.us-west-2.amazonaws.com", "ec2", "us-west-2"},
	{"eks.eu-central-1.amazonaws.com", "eks", "eu-central-1"},
	{"iam.amazonaws.com", "iam", "us-east-1"},
	// global endpoints fall back to the region of their partition
	{"cloudfront.amazonaws.com", "cloudfront", "us-east-1"},
	{"iam.us-gov.amazonaws.com", "iam", "us-gov-west-1"},
	{"iam.cn-north-1.amazonaws.com.cn", "iam", "cn-north-1"},
	{"ec2.cn-northwest-1.amazonaws.com.cn", "ec2", "cn-northwest-1"},
	// regional endpoints of the other partitions
	{"ec2.us-gov-west-1.amazonaws.com", "ec2", "us-gov-west-1"},
	{"ec2.us-iso-east-1.c2s.ic.gov", "ec2", "us-iso-east-1"},
	{"ec2.us-isob-east-1.sc2s.sgov.gov", "ec2", "us-isob-east-1"},
	{"ec2.eusc-de-east-1.amazonaws.eu", "ec2", "eusc-de-east-1"},
	// dual stack, FIPS and older style endpoints
	{"ec2.us-east-1.api.aws", "ec2", "us-east-1"},
	{"s3.dualstack.eu-west-1.amazonaws.com", "s3", "eu-west-1"},
	{"ec2-fips.us-west-2.amazonaws.com", "ec2", "us-west-2"},
	{"s3-us-west-2.amazonaws.com", "s3", "us-west-2"},
	{"s3-fips-us-gov-west-1.amazonaws.com", "s3", "us-gov-west-1"},
	// endpoints prefixed with a resource identifier, or with the service after the region
	{"bucket.s3.us-west-2.amazonaws.com", "s3", "us-west-2"},
	{"abcdef.execute-api.us-east-1.amazonaws.com", "execute-api", "us-east-1"},
	{"api.ecr.us-west-2.amazonaws.com", "ecr", "us-west-2"},
	{"vpce-0123abc.s3.us-east-1.vpce.amazonaws.com", "s3", "us-east-1"},
	{"ABCDEF0123.gr7.us-west-2.eks.amazonaws.com", "eks", "us-west-2"},
	// hosts that carry a port, or that are not AWS endpoints
	{"ec2.us-west-2.amazonaws.com:443", "ec2", "us-west-2"},
	{"example.com", "", "us-east-1"},
}

func TestGetServiceAndRegion(t *testing.T) {
	signer := awsv4{}

	for _, testCase := range TestCases {
		service, region := signer.getServiceAndRegion(testCase.host)
		fmt.Printf("Host: %s Service: %s Region: %s\n", testCase.host, service, region)
		assert.Equal(t, testCase.service, service)
		assert.Equal(t, testCase.region, region)
	}
}

func TestPartitionDNSSuffixes(t *testing.T) {
	suffixes := partitionDNSSuffixes()

	assert.Contains(t, suffixes, "amazonaws.com")
	assert.Contains(t, suffixes, "amazonaws.com.cn")
	assert.Contains(t, suffixes, "api.aws")

	for i := 1; i < len(suffixes); i++ {
		assert.GreaterOrEqual(t, len(suffixes[i-1]), len(suffixes[i]), "suffixes must be sorted by decreasing length")
		assert.NotEqual(t, suffixes[i-1], suffixes[i], "suffixes must not be duplicated")
	}
}
