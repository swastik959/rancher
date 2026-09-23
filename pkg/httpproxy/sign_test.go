package httpproxy

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

var TestCases = []struct{ host, service, region string }{
	{"ec2.us-west-2.amazonaws.com", "ec2", "us-west-2"},
	{"eks.eu-central-1.amazonaws.com", "eks", "eu-central-1"},
	{"iam.amazonaws.com", "iam", "us-east-1"},
	// global services are always signed with the default region of their partition
	{"iam-fips.us-east-1.amazonaws.com", "iam", "us-east-1"},
	{"cloudfront.amazonaws.com", "cloudfront", "us-east-1"},
	{"route53.amazonaws.com", "route53", "us-east-1"},
	{"organizations.us-east-1.amazonaws.com", "organizations", "us-east-1"},
	// global endpoints of regional services
	{"sts.amazonaws.com", "sts", "us-east-1"},
	{"s3.amazonaws.com", "s3", "us-east-1"},
	{"mybucket.s3.amazonaws.com", "s3", "us-east-1"},
	// regional endpoints
	{"kms.ap-southeast-4.amazonaws.com", "kms", "ap-southeast-4"},
	{"ec2.us-west-2.amazonaws.com:443", "ec2", "us-west-2"},
	{"EC2.US-WEST-2.AMAZONAWS.COM", "ec2", "us-west-2"},
	{"ec2-fips.us-west-2.amazonaws.com", "ec2", "us-west-2"},
	{"s3.dualstack.us-west-2.amazonaws.com", "s3", "us-west-2"},
	{"api.ecr.us-west-2.amazonaws.com", "ecr", "us-west-2"},
	{"123456789012.dkr.ecr.us-west-2.amazonaws.com", "ecr", "us-west-2"},
	{"ec2.us-west-2.api.aws", "ec2", "us-west-2"},
	// data plane endpoints are suffixed, rather than prefixed, with the service
	{"mydb.abcdefgh.us-west-2.rds.amazonaws.com", "rds", "us-west-2"},
	{"search-mydomain-abcdefgh.eu-west-1.es.amazonaws.com", "es", "eu-west-1"},
	{"vpce-0123-abcd.ec2.us-west-2.vpce.amazonaws.com", "ec2", "us-west-2"},
	// us-gov partition
	{"ec2.us-gov-west-1.amazonaws.com", "ec2", "us-gov-west-1"},
	{"iam.us-gov.amazonaws.com", "iam", "us-gov-west-1"},
	// china partition, IAM is signed with the regional endpoint rather than the default region
	{"ec2.cn-north-1.amazonaws.com.cn", "ec2", "cn-north-1"},
	{"eks.cn-northwest-1.amazonaws.com.cn", "eks", "cn-northwest-1"},
	{"iam.cn-north-1.amazonaws.com.cn", "iam", "cn-north-1"},
	{"iam.cn-northwest-1.amazonaws.com.cn", "iam", "cn-northwest-1"},
	// other partitions
	{"ec2.us-iso-east-1.c2s.ic.gov", "ec2", "us-iso-east-1"},
	{"ec2.us-isob-east-1.sc2s.sgov.gov", "ec2", "us-isob-east-1"},
	{"ec2.eu-isoe-west-1.cloud.adc-e.uk", "ec2", "eu-isoe-west-1"},
	{"ec2.us-isof-south-1.csp.hci.ic.gov", "ec2", "us-isof-south-1"},
	{"ec2.eusc-de-east-1.amazonaws.eu", "ec2", "eusc-de-east-1"},
	// hosts outside of any known AWS partition have no service to sign for
	{"example.com", "", "us-east-1"},
	{"ec2.us-west-2.example.com", "", "us-east-1"},
	{"", "", "us-east-1"},
}

func TestGetServiceAndRegion(t *testing.T) {
	signer := awsv4{}

	for _, testCase := range TestCases {
		t.Run(testCase.host, func(t *testing.T) {
			service, region := signer.getServiceAndRegion(testCase.host)
			assert.Equal(t, testCase.service, service)
			assert.Equal(t, testCase.region, region)
		})
	}
}
