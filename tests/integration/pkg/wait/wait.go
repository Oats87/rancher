package wait

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/rancher/rancher/tests/integration/pkg/defaults"
	"github.com/sirupsen/logrus"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/watch"
)

type WatchFunc func(namespace string, opts metav1.ListOptions) (watch.Interface, error)
type WatchClusterScopedFunc func(opts metav1.ListOptions) (watch.Interface, error)
type watchFunc func() (watch.Interface, error)

func ClusterScopedList(ctx context.Context, watchFunc WatchClusterScopedFunc, cb func(obj runtime.Object) (bool, error)) error {
	return retryWatch(ctx, func() (watch.Interface, error) {
		return watchFunc(metav1.ListOptions{})
	}, cb)
}

func doWatch(ctx context.Context, watchFunc watchFunc, cb func(obj runtime.Object) (bool, error)) (bool, error) {
	result, err := watchFunc()
	if err != nil {
		logrus.Error("watch failed", err)
		time.Sleep(2 * time.Second)
		return false, nil
	}
	defer func() {
		result.Stop()
		for range result.ResultChan() {
		}
	}()

	for {
		select {
		case <-ctx.Done():
			return false, fmt.Errorf("timeout waiting condition")
		case event, open := <-result.ResultChan():
			if !open {
				return false, nil
			}
			switch event.Type {
			case watch.Added:
				fallthrough
			case watch.Modified:
				fallthrough
			case watch.Deleted:
				done, err := cb(event.Object)
				if err != nil || done {
					return true, err
				}
			}
		}
	}
}

func retryWatch(ctx context.Context, watchFunc watchFunc, cb func(obj runtime.Object) (bool, error)) error {
	ctx, cancel := context.WithTimeout(ctx, time.Duration(defaults.WatchTimeoutSeconds)*time.Second)
	defer cancel()
	for {
		if done, err := doWatch(ctx, watchFunc, cb); err != nil || done {
			return err
		}
	}
}

func Object(ctx context.Context, watchFunc WatchFunc, obj runtime.Object, cb func(obj runtime.Object) (bool, error)) (err error) {
	var last interface{} = obj

	defer func() {
		if err != nil {
			data, _ := json.Marshal(last)
			err = fmt.Errorf("wait failed on %s: %w", data, err)
		}
	}()

	if done, err := cb(obj); err != nil || done {
		return err
	}

	meta, err := meta.Accessor(obj)
	if err != nil {
		return err
	}

	return retryWatch(ctx, func() (watch.Interface, error) {
		return watchFunc(meta.GetNamespace(), metav1.ListOptions{
			FieldSelector:   "metadata.name=" + meta.GetName(),
			ResourceVersion: meta.GetResourceVersion(),
			TimeoutSeconds:  &defaults.WatchTimeoutSeconds,
		})
	}, func(obj runtime.Object) (bool, error) {
		last = obj
		return cb(obj)
	})
}
