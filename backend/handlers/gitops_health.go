package handlers

// Health assessment of the objects a GitOps application applies.
//
// The rules below are ported from github.com/argoproj/gitops-engine
// (pkg/health), Copyright 2020 The Argo Authors, licensed under the Apache
// License, Version 2.0. They are rewritten against the typed objects this
// project already uses rather than imported, to keep the client-go version
// this module pins. Any change in behaviour from the original is ours.

import (
	"fmt"

	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
)

const (
	GHealthHealthy     = "Healthy"
	GHealthProgressing = "Progressing"
	GHealthDegraded    = "Degraded"
	GHealthSuspended   = "Suspended"
	GHealthMissing     = "Missing"
	GHealthUnknown     = "Unknown"
)

// gitopsHealthOrder ranks statuses from best to worst; an application is as
// healthy as its worst object.
var gitopsHealthOrder = map[string]int{
	GHealthHealthy: 0, GHealthSuspended: 1, GHealthProgressing: 2,
	GHealthMissing: 3, GHealthDegraded: 4, GHealthUnknown: 5,
}

func gitopsWorseHealth(a, b string) string {
	if gitopsHealthOrder[b] > gitopsHealthOrder[a] {
		return b
	}
	return a
}

func gitopsFromUnstructured(obj *unstructured.Unstructured, into any) error {
	return runtime.DefaultUnstructuredConverter.FromUnstructured(obj.Object, into)
}

// gitopsObjectHealth returns the health of one live object. Kinds without a rule
// are Healthy once they exist, as in gitops-engine.
func gitopsObjectHealth(obj *unstructured.Unstructured) (string, string) {
	if obj == nil {
		return GHealthMissing, "not in the cluster"
	}
	if obj.GetDeletionTimestamp() != nil {
		return GHealthProgressing, "pending deletion"
	}
	gvk := obj.GroupVersionKind()
	var err error
	switch {
	case gvk.Group == "apps" && gvk.Kind == "Deployment":
		var d appsv1.Deployment
		if err = gitopsFromUnstructured(obj, &d); err == nil {
			return gitopsDeploymentHealth(&d)
		}
	case gvk.Group == "apps" && gvk.Kind == "StatefulSet":
		var s appsv1.StatefulSet
		if err = gitopsFromUnstructured(obj, &s); err == nil {
			return gitopsStatefulSetHealth(&s)
		}
	case gvk.Group == "apps" && gvk.Kind == "DaemonSet":
		var d appsv1.DaemonSet
		if err = gitopsFromUnstructured(obj, &d); err == nil {
			return gitopsDaemonSetHealth(&d)
		}
	case gvk.Group == "apps" && gvk.Kind == "ReplicaSet":
		var r appsv1.ReplicaSet
		if err = gitopsFromUnstructured(obj, &r); err == nil {
			return gitopsReplicaSetHealth(&r)
		}
	case gvk.Group == "" && gvk.Kind == "Service":
		var s corev1.Service
		if err = gitopsFromUnstructured(obj, &s); err == nil {
			if s.Spec.Type == corev1.ServiceTypeLoadBalancer && len(s.Status.LoadBalancer.Ingress) == 0 {
				return GHealthProgressing, "waiting for a load balancer address"
			}
			return GHealthHealthy, ""
		}
	case gvk.Group == "" && gvk.Kind == "PersistentVolumeClaim":
		var p corev1.PersistentVolumeClaim
		if err = gitopsFromUnstructured(obj, &p); err == nil {
			switch p.Status.Phase {
			case corev1.ClaimBound:
				return GHealthHealthy, ""
			case corev1.ClaimPending:
				return GHealthProgressing, "waiting to be bound"
			case corev1.ClaimLost:
				return GHealthDegraded, "the volume was lost"
			}
			return GHealthUnknown, ""
		}
	case gvk.Group == "" && gvk.Kind == "Pod":
		var p corev1.Pod
		if err = gitopsFromUnstructured(obj, &p); err == nil {
			return gitopsPodHealth(&p)
		}
	case gvk.Group == "batch" && gvk.Kind == "Job":
		var j batchv1.Job
		if err = gitopsFromUnstructured(obj, &j); err == nil {
			return gitopsJobHealth(&j)
		}
	case gvk.Group == "networking.k8s.io" && gvk.Kind == "Ingress":
		var i networkingv1.Ingress
		if err = gitopsFromUnstructured(obj, &i); err == nil {
			// gitops-engine waits for an address; many controllers never
			// publish one, so that would leave an Ingress Progressing forever.
			// An Ingress that exists is Healthy here.
			return GHealthHealthy, ""
		}
	default:
		return GHealthHealthy, ""
	}
	return GHealthUnknown, err.Error()
}

func gitopsDeploymentHealth(d *appsv1.Deployment) (string, string) {
	if d.Spec.Paused {
		return GHealthSuspended, "deployment is paused"
	}
	if d.Generation > d.Status.ObservedGeneration {
		return GHealthProgressing, "waiting for the new spec to be observed"
	}
	for _, c := range d.Status.Conditions {
		if c.Type == appsv1.DeploymentProgressing && c.Reason == "ProgressDeadlineExceeded" {
			return GHealthDegraded, fmt.Sprintf("deployment %q exceeded its progress deadline", d.Name)
		}
	}
	switch {
	case d.Spec.Replicas != nil && d.Status.UpdatedReplicas < *d.Spec.Replicas:
		return GHealthProgressing, fmt.Sprintf("%d of %d new replicas updated", d.Status.UpdatedReplicas, *d.Spec.Replicas)
	case d.Status.Replicas > d.Status.UpdatedReplicas:
		return GHealthProgressing, fmt.Sprintf("%d old replicas pending termination", d.Status.Replicas-d.Status.UpdatedReplicas)
	case d.Status.AvailableReplicas < d.Status.UpdatedReplicas:
		return GHealthProgressing, fmt.Sprintf("%d of %d updated replicas available", d.Status.AvailableReplicas, d.Status.UpdatedReplicas)
	}
	return GHealthHealthy, ""
}

func gitopsStatefulSetHealth(s *appsv1.StatefulSet) (string, string) {
	if s.Status.ObservedGeneration == 0 || s.Generation > s.Status.ObservedGeneration {
		return GHealthProgressing, "waiting for the new spec to be observed"
	}
	if s.Spec.Replicas != nil && s.Status.ReadyReplicas < *s.Spec.Replicas {
		return GHealthProgressing, fmt.Sprintf("waiting for %d pods to be ready", *s.Spec.Replicas-s.Status.ReadyReplicas)
	}
	if s.Spec.UpdateStrategy.Type == appsv1.RollingUpdateStatefulSetStrategyType && s.Spec.UpdateStrategy.RollingUpdate != nil &&
		s.Spec.Replicas != nil && s.Spec.UpdateStrategy.RollingUpdate.Partition != nil {
		want := *s.Spec.Replicas - *s.Spec.UpdateStrategy.RollingUpdate.Partition
		if s.Status.UpdatedReplicas < want {
			return GHealthProgressing, fmt.Sprintf("partitioned rollout: %d of %d pods updated", s.Status.UpdatedReplicas, want)
		}
		return GHealthHealthy, ""
	}
	if s.Spec.UpdateStrategy.Type == appsv1.OnDeleteStatefulSetStrategyType {
		return GHealthHealthy, ""
	}
	if s.Status.UpdateRevision != "" && s.Status.UpdateRevision != s.Status.CurrentRevision {
		return GHealthProgressing, fmt.Sprintf("rolling update: %d pods at the new revision", s.Status.UpdatedReplicas)
	}
	return GHealthHealthy, ""
}

func gitopsDaemonSetHealth(d *appsv1.DaemonSet) (string, string) {
	if d.Generation > d.Status.ObservedGeneration {
		return GHealthProgressing, "waiting for the new spec to be observed"
	}
	if d.Spec.UpdateStrategy.Type == appsv1.OnDeleteDaemonSetStrategyType {
		return GHealthHealthy, ""
	}
	if d.Status.UpdatedNumberScheduled < d.Status.DesiredNumberScheduled {
		return GHealthProgressing, fmt.Sprintf("%d of %d pods updated", d.Status.UpdatedNumberScheduled, d.Status.DesiredNumberScheduled)
	}
	if d.Status.NumberAvailable < d.Status.DesiredNumberScheduled {
		return GHealthProgressing, fmt.Sprintf("%d of %d pods available", d.Status.NumberAvailable, d.Status.DesiredNumberScheduled)
	}
	return GHealthHealthy, ""
}

func gitopsReplicaSetHealth(r *appsv1.ReplicaSet) (string, string) {
	if r.Generation > r.Status.ObservedGeneration {
		return GHealthProgressing, "waiting for the new spec to be observed"
	}
	for _, c := range r.Status.Conditions {
		if c.Type == appsv1.ReplicaSetReplicaFailure && c.Status == corev1.ConditionTrue {
			return GHealthDegraded, c.Message
		}
	}
	if r.Spec.Replicas != nil && r.Status.AvailableReplicas < *r.Spec.Replicas {
		return GHealthProgressing, fmt.Sprintf("%d of %d replicas available", r.Status.AvailableReplicas, *r.Spec.Replicas)
	}
	return GHealthHealthy, ""
}

func gitopsPodHealth(p *corev1.Pod) (string, string) {
	switch p.Status.Phase {
	case corev1.PodSucceeded:
		return GHealthHealthy, p.Status.Message
	case corev1.PodFailed:
		return GHealthDegraded, p.Status.Message
	case corev1.PodPending:
		return GHealthProgressing, p.Status.Message
	case corev1.PodRunning:
		for _, cs := range p.Status.ContainerStatuses {
			if w := cs.State.Waiting; w != nil && (w.Reason == "CrashLoopBackOff" || w.Reason == "ImagePullBackOff" || w.Reason == "ErrImagePull") {
				return GHealthDegraded, w.Reason
			}
		}
		for _, c := range p.Status.Conditions {
			if c.Type == corev1.PodReady && c.Status == corev1.ConditionTrue {
				return GHealthHealthy, ""
			}
		}
		return GHealthProgressing, "not ready"
	}
	return GHealthUnknown, p.Status.Message
}

func gitopsJobHealth(j *batchv1.Job) (string, string) {
	for _, c := range j.Status.Conditions {
		if c.Status != corev1.ConditionTrue {
			continue
		}
		switch c.Type {
		case batchv1.JobFailed:
			return GHealthDegraded, c.Message
		case batchv1.JobComplete:
			return GHealthHealthy, c.Message
		case batchv1.JobSuspended:
			return GHealthSuspended, c.Message
		}
	}
	return GHealthProgressing, "running"
}
