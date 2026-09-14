"use client";

import ResourceBrowser from "@/app/components/k8s/ResourceBrowser";

export default function Page() {
  return (
    <ResourceBrowser
      kind="daemonsets"
      title="DaemonSets"
      subtitle="Per-node workloads and whether they are scheduled on every node they should be"
      namespaced={true}
      columns={[
        { id: "name", label: "DaemonSet", mono: true, truncate: true },
        { id: "namespace", label: "Namespace" },
        { id: "desired", label: "Desired", align: "right" },
        { id: "current", label: "Current", align: "right" },
        { id: "ready", label: "Ready", align: "right" },
        { id: "upToDate", label: "Up-to-date", align: "right" },
        { id: "image", label: "Image", mono: true, truncate: true },
        { id: "age", label: "Age", align: "right" },
      ]}
    />
  );
}
