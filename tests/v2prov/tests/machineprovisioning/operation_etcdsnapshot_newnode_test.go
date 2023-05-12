package machineprovisioning

import (
	provisioningv1 "github.com/rancher/rancher/pkg/apis/provisioning.cattle.io/v1"
	rkev1 "github.com/rancher/rancher/pkg/apis/rke.cattle.io/v1"
	"github.com/rancher/rancher/tests/v2prov/clients"
	"github.com/rancher/rancher/tests/v2prov/cluster"
	"github.com/rancher/rancher/tests/v2prov/defaults"
	"github.com/rancher/rancher/tests/v2prov/namespace"
	"github.com/rancher/rancher/tests/v2prov/objectstore"
	"github.com/rancher/rancher/tests/v2prov/operations"
	"github.com/rancher/wrangler/pkg/name"
	"github.com/stretchr/testify/assert"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"testing"
	"time"
)

// Test_Operation_MP_EtcdSnapshotOperationsOnNewNode uses Minio as an object store to store S3 snapshots. It creates a 2 node machine provisioned cluster with a controlplane+worker and
// etcd node, creates a configmap, takes a snapshot of the cluster, deletes the configmap, then deletes the etcd machine/node.
// It then creates a new etcd node and restores from local snapshot file.
func Test_Operation_MP_EtcdSnapshotOperationsOnNewNode(t *testing.T) {
	clients, err := clients.New()
	if err != nil {
		t.Fatal(err)
	}
	defer clients.Close()

	newNs, err := namespace.Random(clients)
	if err != nil {
		t.Fatal(err)
	}

	osInfo, err := objectstore.GetObjectStore(clients, newNs.Name, "store0", "s3snapshots")
	if err != nil {
		t.Fatal(err)
	}

	c, err := cluster.New(clients, &provisioningv1.Cluster{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-mp-etcd-snapshot-operations-on-new-node",
			Namespace: newNs.Name,
		},
		Spec: provisioningv1.ClusterSpec{
			RKEConfig: &provisioningv1.RKEConfig{
				RKEClusterSpecCommon: rkev1.RKEClusterSpecCommon{
					ETCD: &rkev1.ETCD{
						S3: &rkev1.ETCDSnapshotS3{
							Endpoint:            osInfo.Endpoint,
							EndpointCA:          osInfo.Cert,
							Bucket:              osInfo.Bucket,
							CloudCredentialName: osInfo.CloudCredentialName,
							Folder:              "testfolder",
						},
					},
				},
				MachinePools: []provisioningv1.RKEMachinePool{
					{
						EtcdRole: true,
						Quantity: &defaults.One,
					},
					{
						ControlPlaneRole: true,
						WorkerRole:       true,
						Quantity:         &defaults.One,
					},
				},
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	c, err = cluster.WaitForCreate(clients, c)
	if err != nil {
		t.Fatal(err)
	}

	cm := corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name: "my-configmap-" + name.Hex(time.Now().String(), 10),
		},
		Data: map[string]string{
			"test": "wow",
		},
	}

	snapshot := operations.RunSnapshotCreateTest(t, clients, c, cm, "s3")
	assert.NotNil(t, snapshot)
	// Scale etcd nodes to 0
	c, err = operations.Scale(clients, c, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	// Scale etcd nodes to 1
	c, err = operations.Scale(clients, c, 0, 1)
	if err != nil {
		t.Fatal(err)
	}
	operations.RunSnapshotRestoreTest(t, clients, c, snapshot.Name, cm)
	err = cluster.EnsureMinimalConflictsWithThreshold(clients, c, cluster.SaneConflictMessageThreshold)
	assert.NoError(t, err)
}
