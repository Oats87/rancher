package plansecret

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"strings"

	"github.com/rancher/rancher/pkg/controllers/provisioningv2/rke2"
	capicontrollers "github.com/rancher/rancher/pkg/generated/controllers/cluster.x-k8s.io/v1beta1"
	rkev1controllers "github.com/rancher/rancher/pkg/generated/controllers/rke.cattle.io/v1"
	"github.com/rancher/rancher/pkg/provisioningv2/rke2/planner"
	"github.com/rancher/rancher/pkg/wrangler"
	corecontrollers "github.com/rancher/wrangler/pkg/generated/controllers/core/v1"
	"github.com/sirupsen/logrus"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	capi "sigs.k8s.io/cluster-api/api/v1beta1"
	"sigs.k8s.io/cluster-api/util/conditions"
)

type handler struct {
	secrets             corecontrollers.SecretClient
	machinesCache       capicontrollers.MachineCache
	machinesClient      capicontrollers.MachineClient
	etcdSnapshotsClient rkev1controllers.ETCDSnapshotClient
	etcdSnapshotsCache  rkev1controllers.ETCDSnapshotCache
}

func Register(ctx context.Context, clients *wrangler.Context) {
	h := handler{
		secrets:             clients.Core.Secret(),
		machinesCache:       clients.CAPI.Machine().Cache(),
		machinesClient:      clients.CAPI.Machine(),
		etcdSnapshotsClient: clients.RKE.ETCDSnapshot(),
		etcdSnapshotsCache:  clients.RKE.ETCDSnapshot().Cache(),
	}
	clients.Core.Secret().OnChange(ctx, "plan-secret", h.OnChange)
}

func (h *handler) OnChange(key string, secret *corev1.Secret) (*corev1.Secret, error) {
	if secret == nil || secret.Type != rke2.SecretTypeMachinePlan || len(secret.Data) == 0 {
		return secret, nil
	}

	logrus.Debugf("[plansecret] reconciling secret %s/%s", secret.Namespace, secret.Name)

	node, err := planner.SecretToNode(secret)
	if err != nil {
		return secret, err
	}

	if v, ok := node.PeriodicOutput["etcd-snapshot-list-local"]; ok && v.ExitCode == 0 && len(v.Stdout) > 0 {
		if err := h.reconcileEtcdSnapshotList(secret, false, v.Stdout); err != nil {
			logrus.Errorf("[plansecret] error reconciling local snapshot list for secret %s/%s: %v", secret.Namespace, secret.Name, err)
		}
	}

	if v, ok := node.PeriodicOutput["etcd-snapshot-list-s3"]; ok && v.ExitCode == 0 && len(v.Stdout) > 0 {
		if err := h.reconcileEtcdSnapshotList(secret, true, v.Stdout); err != nil {
			logrus.Errorf("[plansecret] error reconciling S3 snapshot list for secret %s/%s: %v", secret.Namespace, secret.Name, err)
		}
	}

	appliedChecksum := string(secret.Data["applied-checksum"])
	failedChecksum := string(secret.Data["failed-checksum"])
	plan := secret.Data["plan"]

	if appliedChecksum == planner.PlanHash(plan) && !bytes.Equal(plan, secret.Data["appliedPlan"]) {
		secret = secret.DeepCopy()
		secret.Data["appliedPlan"] = plan
		// don't return the secret at this point, we want to attempt to update the machine status later on
		secret, err = h.secrets.Update(secret)
		if err != nil {
			return secret, err
		}
	}

	if failedChecksum == planner.PlanHash(plan) {
		logrus.Debugf("[plansecret] %s/%s: rv: %s: Detected failed plan application, reconciling machine PlanApplied condition to error", secret.Namespace, secret.Name, secret.ResourceVersion)
		err = h.reconcileMachinePlanAppliedCondition(secret, fmt.Errorf("error applying plan -- check rancher-system-agent.service logs on node for more information"))
		return secret, err
	}

	logrus.Debugf("[plansecret] %s/%s: rv: %s: Reconciling machine PlanApplied condition to nil", secret.Namespace, secret.Name, secret.ResourceVersion)
	err = h.reconcileMachinePlanAppliedCondition(secret, nil)
	return secret, err
}

func (h *handler) reconcileMachinePlanAppliedCondition(secret *corev1.Secret, planAppliedErr error) error {
	if secret == nil {
		logrus.Debug("[plansecret] secret was nil when reconciling machine status")
		return nil
	}

	condition := capi.ConditionType(rke2.PlanApplied)

	machineName, ok := secret.Labels[rke2.MachineNameLabel]
	if !ok {
		return fmt.Errorf("did not find machine label on secret %s/%s", secret.Namespace, secret.Name)
	}

	machine, err := h.machinesCache.Get(secret.Namespace, machineName)
	if err != nil {
		return err
	}

	machine = machine.DeepCopy()

	var needsUpdate bool
	if planAppliedErr != nil &&
		(conditions.GetMessage(machine, condition) != planAppliedErr.Error() ||
			*conditions.GetSeverity(machine, condition) != capi.ConditionSeverityError ||
			!conditions.IsFalse(machine, condition) ||
			conditions.GetReason(machine, condition) != "Error") {
		logrus.Debugf("[plansecret] machine %s/%s: marking PlanApplied as false", machine.Namespace, machine.Name)
		conditions.MarkFalse(machine, condition, "Error", capi.ConditionSeverityError, planAppliedErr.Error())
		needsUpdate = true
	} else if planAppliedErr == nil && !conditions.IsTrue(machine, condition) {
		logrus.Debugf("[plansecret] machine %s/%s: marking PlanApplied as true", machine.Namespace, machine.Name)
		conditions.MarkTrue(machine, condition)
		needsUpdate = true
	}

	if needsUpdate {
		logrus.Debugf("[plansecret] machine %s/%s: updating status of machine to reconcile for condition with error: %+v", machine.Namespace, machine.Name, planAppliedErr)
		_, err = h.machinesClient.UpdateStatus(machine)
	}

	return err
}

func (h *handler) reconcileEtcdSnapshotList(secret *corev1.Secret, s3 bool, listStdout []byte) error {
	cnl := secret.Labels[rke2.ClusterNameLabel]
	if len(cnl) == 0 {
		return fmt.Errorf("node secret did not have label %s", rke2.ClusterNameLabel)
	}

	machineName, ok := secret.Labels[rke2.MachineNameLabel]
	if !ok {
		return fmt.Errorf("did not find machine label on secret %s/%s", secret.Namespace, secret.Name)
	}

	nodeName := "s3"

	if !s3 {
		machine, err := h.machinesCache.Get(secret.Namespace, machineName)
		if err != nil {
			return err
		}
		if machine.Status.NodeRef != nil && machine.Status.NodeRef.Name != "" {
			nodeName = machine.Status.NodeRef.Name
		} else {
			return fmt.Errorf("error finding corresponding node via noderef for machine %s/%s", machine.Namespace, machine.Name)
		}
	}

	etcdSnapshotsOnNode := outputToEtcdSnapshots(cnl, listStdout)
	ls, err := labels.Parse(fmt.Sprintf("%s=%s,%s=%s", rke2.ClusterNameLabel, cnl, rke2.NodeNameLabel, nodeName))
	if err != nil {
		return err
	}

	etcdSnapshots, err := h.etcdSnapshotsCache.List(secret.Namespace, ls)
	if err != nil {
		return err
	}

	for _, v := range etcdSnapshots {
		if _, ok := etcdSnapshotsOnNode[v.Name]; !ok && v.Status.Missing {
			// delete the etcd snapshot as it is likely missing
			logrus.Infof("Deleting etcd snapshot %s/%s", v.Namespace, v.Name)
			if err := h.etcdSnapshotsClient.Delete(v.Namespace, v.Name, &metav1.DeleteOptions{}); err != nil {
				return err
			}
		}
	}
	return nil
}

type snapshot struct {
	Name     string
	Location string
	Size     string
	Created  string
	S3       bool
}

func outputToEtcdSnapshots(clusterName string, collectedOutput []byte) map[string]*snapshot {
	scanner := bufio.NewScanner(bytes.NewBuffer(collectedOutput))
	snapshots := make(map[string]*snapshot)
	for scanner.Scan() {
		line := scanner.Text()
		if s := strings.Fields(line); len(s) == 3 || len(s) == 4 {
			switch len(s) {
			case 3:
				if strings.ToLower(s[0]) == "name" &&
					strings.ToLower(s[1]) == "size" &&
					strings.ToLower(s[2]) == "created" {
					continue
				}
			case 4:
				if strings.ToLower(s[0]) == "name" &&
					strings.ToLower(s[1]) == "location" &&
					strings.ToLower(s[2]) == "size" &&
					strings.ToLower(s[3]) == "created" {
					continue
				}
			}
			ss, err := generateEtcdSnapshotFromListOutput(line)
			if err != nil {
				logrus.Errorf("error parsing etcd snapshot output (%s) to etcd snapshot: %v", line, err)
				continue
			}
			suffix := "local"
			if ss.S3 {
				suffix = "s3"
			}
			snapshots[fmt.Sprintf("%s-%s-%s", clusterName, ss.Name, suffix)] = ss
		}
	}
	return snapshots
}

func generateEtcdSnapshotFromListOutput(input string) (*snapshot, error) {
	snapshotData := strings.Fields(input)
	switch len(snapshotData) {
	case 3:
		return &snapshot{
			Name:    snapshotData[0],
			Size:    snapshotData[1],
			Created: snapshotData[2],
			S3:      true,
		}, nil
	case 4:
		return &snapshot{
			Name:     snapshotData[0],
			Location: snapshotData[1],
			Size:     snapshotData[2],
			Created:  snapshotData[3],
			S3:       false,
		}, nil
	}
	return nil, fmt.Errorf("input (%s) did not have 3 or 4 fields", input)
}
