package bootstrap

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"testing"
	"time"

	rkev1 "github.com/rancher/rancher/pkg/apis/rke.cattle.io/v1"
	"github.com/rancher/rancher/pkg/capr"
	"github.com/rancher/rancher/pkg/namespace"
	"github.com/rancher/rancher/pkg/settings"
	ctrlfake "github.com/rancher/wrangler/v3/pkg/generic/fake"
	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"
	v1apps "k8s.io/api/apps/v1"
	v1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/kubernetes/fake"
	capi "sigs.k8s.io/cluster-api/api/core/v1beta2"
)

func Test_getBootstrapSecret(t *testing.T) {
	type args struct {
		secretName    string
		os            string
		namespaceName string
		path          string
		command       string
		body          string
	}

	tests := []struct {
		name string
		args args
	}{
		{
			name: "Checking Linux Install Script",
			args: args{
				os:            capr.DefaultMachineOS,
				secretName:    "mybestlinuxsecret",
				command:       "sh",
				namespaceName: "myfavoritelinuxnamespace",
				path:          "/system-agent-install.sh",
				body:          "#!/usr/bin/env sh",
			},
		},
		{
			name: "Checking Windows Install Script",
			args: args{
				os:            capr.WindowsMachineOS,
				secretName:    "mybestwindowssecret",
				command:       "powershell",
				namespaceName: "myfavoritewindowsnamespace",
				path:          "/wins-agent-install.ps1",
				body:          "Invoke-WinsInstaller @PSBoundParameters",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// arrange
			expectHash := sha256.Sum256([]byte("thisismytokenandiwillprotectit"))
			expectEncodedHash := base64.URLEncoding.EncodeToString(expectHash[:])
			a := assert.New(t)
			ctrl := gomock.NewController(t)
			handler := handler{
				serviceAccountCache: getServiceAccountCacheMock(ctrl, tt.args.namespaceName, tt.args.secretName),
				secretCache:         getSecretCacheMock(ctrl, tt.args.namespaceName, tt.args.secretName),
				secretClient:        getSecretClientMock(ctrl),
				deploymentCache:     getDeploymentCacheMock(ctrl),
				machineCache:        getMachineCacheMock(ctrl, tt.args.namespaceName, tt.args.os),
				k8s:                 fake.NewSimpleClientset(),
			}

			//act
			err := settings.ServerURL.Set("localhost")
			a.Nil(err)
			err = settings.SystemAgentInstallScript.Set("https://raw.githubusercontent.com/rancher/system-agent/main/install.sh")
			a.Nil(err)
			err = settings.SystemAgentInstallerImage.Set("rancher/system-agent-installer-")
			a.Nil(err)

			serviceAccount, err := handler.serviceAccountCache.Get(tt.args.namespaceName, tt.args.secretName)
			a.Nil(err)
			machine, err := handler.machineCache.Get(tt.args.namespaceName, tt.args.os)
			a.Nil(err)
			secret, err := handler.getBootstrapSecret(tt.args.namespaceName, tt.args.secretName, []v1.EnvVar{}, machine, nil, "")
			a.Nil(err)

			// assert
			a.NotNil(secret)
			a.NotNil(serviceAccount)
			a.NotNil(machine)
			a.NotNil(expectHash)
			a.NotEmpty(expectEncodedHash)

			a.Equal(tt.args.secretName, secret.Name)
			a.Equal(tt.args.namespaceName, secret.Namespace)
			a.Equal(tt.args.secretName, serviceAccount.Name)
			a.Equal(tt.args.namespaceName, serviceAccount.Namespace)
			a.Equal(tt.args.os, machine.Name)
			a.Equal(tt.args.namespaceName, machine.Namespace)

			a.Equal("rke.cattle.io/bootstrap", string(secret.Type))
			data := string(secret.Data["value"])
			a.Contains(data, fmt.Sprintf("CATTLE_TOKEN=\"%s\"", expectEncodedHash))

			switch tt.args.os {

			case capr.DefaultMachineOS:
				a.Equal(tt.args.os, capr.DefaultMachineOS)
				a.Contains(data, "#!/usr/bin")
				a.True(machine.GetLabels()[capr.CattleOSLabel] == capr.DefaultMachineOS)
				a.True(machine.GetLabels()[capr.ControlPlaneRoleLabel] == "true")
				a.True(machine.GetLabels()[capr.EtcdRoleLabel] == "true")
				a.True(machine.GetLabels()[capr.WorkerRoleLabel] == "true")
				a.Contains(data, "CATTLE_SERVER=localhost")
				a.Contains(data, "CATTLE_ROLE_NONE=true")

			case capr.WindowsMachineOS:
				a.Equal(tt.args.os, capr.WindowsMachineOS)
				a.Contains(data, "Invoke-WinsInstaller")
				a.True(machine.GetLabels()[capr.CattleOSLabel] == capr.WindowsMachineOS)
				a.True(machine.GetLabels()[capr.ControlPlaneRoleLabel] == "false")
				a.True(machine.GetLabels()[capr.EtcdRoleLabel] == "false")
				a.True(machine.GetLabels()[capr.WorkerRoleLabel] == "true")
				a.Contains(data, "$env:CATTLE_SERVER=\"localhost\"")
				a.Contains(data, "CATTLE_ROLE_NONE=\"true\"")
				a.Contains(data, "$env:CSI_PROXY_URL")
				a.Contains(data, "$env:CSI_PROXY_VERSION")
				a.Contains(data, "$env:CSI_PROXY_KUBELET_PATH")
			}
		})
	}
}

func getMachineCacheMock(ctrl *gomock.Controller, namespace, os string) *ctrlfake.MockCacheInterface[*capi.Machine] {
	mockMachineCache := ctrlfake.NewMockCacheInterface[*capi.Machine](ctrl)
	mockMachineCache.EXPECT().Get(namespace, capr.DefaultMachineOS).DoAndReturn(func(namespace, name string) (*capi.Machine, error) {
		return &capi.Machine{
			ObjectMeta: metav1.ObjectMeta{
				Name:      os,
				Namespace: namespace,
				Labels: map[string]string{
					capr.ControlPlaneRoleLabel: "true",
					capr.EtcdRoleLabel:         "true",
					capr.WorkerRoleLabel:       "true",
					capr.CattleOSLabel:         os,
				},
			},
			Spec: capi.MachineSpec{
				InfrastructureRef: capi.ContractVersionedObjectReference{
					APIGroup: capr.RKEMachineAPIGroup,
				},
			},
		}, nil
	}).AnyTimes()

	mockMachineCache.EXPECT().Get(namespace, capr.WindowsMachineOS).DoAndReturn(func(namespace, name string) (*capi.Machine, error) {
		return &capi.Machine{
			ObjectMeta: metav1.ObjectMeta{
				Name:      os,
				Namespace: namespace,
				Labels: map[string]string{
					capr.ControlPlaneRoleLabel: "false",
					capr.EtcdRoleLabel:         "false",
					capr.WorkerRoleLabel:       "true",
					capr.CattleOSLabel:         os,
				},
			},
			Spec: capi.MachineSpec{
				InfrastructureRef: capi.ContractVersionedObjectReference{
					APIGroup: capr.RKEMachineAPIGroup,
				},
			},
		}, nil
	}).AnyTimes()
	return mockMachineCache
}

func getDeploymentCacheMock(ctrl *gomock.Controller) *ctrlfake.MockCacheInterface[*v1apps.Deployment] {
	mockDeploymentCache := ctrlfake.NewMockCacheInterface[*v1apps.Deployment](ctrl)
	mockDeploymentCache.EXPECT().Get(namespace.System, "rancher").DoAndReturn(func(namespace, name string) (*v1apps.Deployment, error) {
		return &v1apps.Deployment{
			Spec: v1apps.DeploymentSpec{
				Template: v1.PodTemplateSpec{
					Spec: v1.PodSpec{
						Containers: []v1.Container{
							{
								Name: "rancher",
								Ports: []v1.ContainerPort{
									{
										HostPort: 8080,
									},
								},
							},
						},
					},
				},
			},
		}, nil
	}).AnyTimes()
	return mockDeploymentCache
}

func getSecretCacheMock(ctrl *gomock.Controller, namespace, saName string) *ctrlfake.MockCacheInterface[*v1.Secret] {
	mockSecretCache := ctrlfake.NewMockCacheInterface[*v1.Secret](ctrl)
	selector := labels.Set{"cattle.io/service-account.name": saName}.AsSelector()
	mockSecretCache.EXPECT().List(namespace, selector).DoAndReturn(func(namespace string, selector labels.Selector) ([]*v1.Secret, error) {
		return []*v1.Secret{
			{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: namespace,
					Name:      saName + "-secret",
					Annotations: map[string]string{
						"kubernetes.io/service-account.name": saName,
					},
					Labels: map[string]string{
						"cattle.io/service-account.name": saName,
					},
				},
				Immutable: nil,
				Data: map[string][]byte{
					"token": []byte("thisismytokenandiwillprotectit"),
				},
				StringData: nil,
				Type:       "kubernetes.io/service-account-token",
			},
		}, nil
	}).AnyTimes()
	return mockSecretCache
}

func getServiceAccountCacheMock(ctrl *gomock.Controller, namespace, name string) *ctrlfake.MockCacheInterface[*v1.ServiceAccount] {
	mockServiceAccountCache := ctrlfake.NewMockCacheInterface[*v1.ServiceAccount](ctrl)
	mockServiceAccountCache.EXPECT().Get(namespace, name).DoAndReturn(func(namespace, name string) (*v1.ServiceAccount, error) {
		return &v1.ServiceAccount{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: namespace,
				Name:      name,
			},
			Secrets: []v1.ObjectReference{
				{
					Namespace: namespace,
					Name:      name,
				},
			},
		}, nil
	}).AnyTimes()
	return mockServiceAccountCache
}

func getSecretClientMock(ctrl *gomock.Controller) *ctrlfake.MockClientInterface[*v1.Secret, *v1.SecretList] {
	mock := ctrlfake.NewMockClientInterface[*v1.Secret, *v1.SecretList](ctrl)
	mock.EXPECT().Update(gomock.Any()).DoAndReturn(func(secret *v1.Secret) (*v1.Secret, error) {
		return secret, nil
	})
	return mock
}

func TestShouldCreateBootstrapSecret(t *testing.T) {
	tests := []struct {
		phase    capi.MachinePhase
		expected bool
	}{
		{
			phase:    capi.MachinePhasePending,
			expected: true,
		},
		{
			phase:    capi.MachinePhaseProvisioning,
			expected: true,
		},
		{
			phase:    capi.MachinePhaseProvisioned,
			expected: true,
		},
		{
			phase:    capi.MachinePhaseRunning,
			expected: true,
		},
		{
			phase:    capi.MachinePhaseDeleting,
			expected: false,
		},
		{
			phase:    capi.MachinePhaseDeleted,
			expected: false,
		},
		{
			phase:    capi.MachinePhaseFailed,
			expected: false,
		},
		{
			phase:    capi.MachinePhaseUnknown,
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(string(tt.phase), func(t *testing.T) {
			actual := shouldCreateBootstrapSecret(tt.phase)
			assert.Equal(t, tt.expected, actual)
		})
	}
}

func Test_reconcileMachinePreTerminateAnnotation(t *testing.T) {
	const (
		testNamespace   = "fleet-default"
		testClusterName = "test-cluster"
	)

	newBootstrap := func() *rkev1.RKEBootstrap {
		return &rkev1.RKEBootstrap{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test-bootstrap",
				Namespace: testNamespace,
				OwnerReferences: []metav1.OwnerReference{
					{
						APIVersion: capi.GroupVersion.String(),
						Kind:       "Machine",
						Name:       "test-machine",
					},
				},
			},
			Spec: rkev1.RKEBootstrapSpec{ClusterName: testClusterName},
		}
	}

	newEtcdMachine := func(name string, deleting bool) *capi.Machine {
		machine := &capi.Machine{
			ObjectMeta: metav1.ObjectMeta{
				Name:        name,
				Namespace:   testNamespace,
				Labels:      map[string]string{capr.EtcdRoleLabel: "true", capi.ClusterNameLabel: testClusterName},
				Annotations: map[string]string{},
			},
			Spec:   capi.MachineSpec{ClusterName: testClusterName},
			Status: capi.MachineStatus{NodeRef: capi.MachineNodeReference{Name: name}},
		}
		if deleting {
			machine.DeletionTimestamp = &metav1.Time{Time: time.Now()}
			machine.Annotations[capiMachinePreTerminateAnnotation] = capiMachinePreTerminateAnnotationOwner
		}
		return machine
	}

	t.Run("deleting etcd machine has its pre-terminate hook removed", func(t *testing.T) {
		// A deleting etcd machine must not have the removal of its pre-terminate hook deferred, otherwise
		// CAPI is never able to finish deleting the machine and cluster deletion hangs indefinitely.
		ctrl := gomock.NewController(t)
		bootstrap := newBootstrap()
		deletingMachine := newEtcdMachine("test-machine", true)
		remainingMachine := newEtcdMachine("other-machine", false)

		machineCache := ctrlfake.NewMockCacheInterface[*capi.Machine](ctrl)
		machineCache.EXPECT().Get(testNamespace, "test-machine").Return(deletingMachine, nil).AnyTimes()
		machineCache.EXPECT().List(testNamespace, gomock.Any()).Return([]*capi.Machine{deletingMachine, remainingMachine}, nil).AnyTimes()

		var updated *capi.Machine
		machineClient := ctrlfake.NewMockClientInterface[*capi.Machine, *capi.MachineList](ctrl)
		machineClient.EXPECT().Update(gomock.Any()).DoAndReturn(func(machine *capi.Machine) (*capi.Machine, error) {
			updated = machine
			return machine, nil
		}).Times(1)

		capiClusterCache := ctrlfake.NewMockCacheInterface[*capi.Cluster](ctrl)
		capiClusterCache.EXPECT().Get(testNamespace, testClusterName).Return(&capi.Cluster{
			ObjectMeta: metav1.ObjectMeta{Name: testClusterName, Namespace: testNamespace},
			Spec: capi.ClusterSpec{
				ControlPlaneRef: capi.ContractVersionedObjectReference{
					APIGroup: "rke.cattle.io",
					Kind:     "RKEControlPlane",
					Name:     testClusterName,
				},
			},
		}, nil).AnyTimes()

		rkeControlPlaneCache := ctrlfake.NewMockCacheInterface[*rkev1.RKEControlPlane](ctrl)
		rkeControlPlaneCache.EXPECT().Get(testNamespace, testClusterName).Return(&rkev1.RKEControlPlane{
			ObjectMeta: metav1.ObjectMeta{Name: testClusterName, Namespace: testNamespace},
		}, nil).AnyTimes()

		secretCache := ctrlfake.NewMockCacheInterface[*v1.Secret](ctrl)
		secretCache.EXPECT().Get(testNamespace, gomock.Any()).Return(nil, apierrors.NewNotFound(schema.GroupResource{Resource: "secrets"}, "")).AnyTimes()

		h := handler{
			machineCache:     machineCache,
			machineClient:    machineClient,
			capiClusterCache: capiClusterCache,
			rkeControlPlanes: rkeControlPlaneCache,
			secretCache:      secretCache,
		}

		_, err := h.reconcileMachinePreTerminateAnnotation(bootstrap)
		assert.Nil(t, err)
		assert.NotNil(t, updated)
		assert.NotContains(t, updated.Annotations, capiMachinePreTerminateAnnotation)
	})

	t.Run("running etcd machine gets the pre-terminate hook", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		bootstrap := newBootstrap()
		machine := newEtcdMachine("test-machine", false)

		machineCache := ctrlfake.NewMockCacheInterface[*capi.Machine](ctrl)
		machineCache.EXPECT().Get(testNamespace, "test-machine").Return(machine, nil).AnyTimes()

		var updated *capi.Machine
		machineClient := ctrlfake.NewMockClientInterface[*capi.Machine, *capi.MachineList](ctrl)
		machineClient.EXPECT().Update(gomock.Any()).DoAndReturn(func(machine *capi.Machine) (*capi.Machine, error) {
			updated = machine
			return machine, nil
		}).Times(1)

		h := handler{machineCache: machineCache, machineClient: machineClient}

		_, err := h.reconcileMachinePreTerminateAnnotation(bootstrap)
		assert.Nil(t, err)
		assert.NotNil(t, updated)
		assert.Equal(t, capiMachinePreTerminateAnnotationOwner, updated.Annotations[capiMachinePreTerminateAnnotation])
	})
}
